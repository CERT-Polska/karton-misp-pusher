from uuid import UUID, uuid5

from karton.core import Config, Karton, Task
from mwdb_iocextract import parse  # type: ignore
from mwdblib.util import config_dhash  # type: ignore
from pymisp import ExpandedPyMISP, MISPEvent


class MispPusher(Karton):
    """
    Transforms configurations using mwdb-iocextract and pushes to a
    configured MISP instance.
    """

    identity = "karton.misp-pusher"
    filters = [{"type": "config"}]

    # Arbitrary root namespace for MISP UUIDs.
    # Event UUIDs are generated deterministically from a (root, cfg_hash) pair.
    CONFIG_NAMESPACE = UUID("dc232ceb-a523-41a1-98f4-8d3d52ec6eff")

    def process(self, task: Task) -> None:  # type: ignore
        config = task.get_payload("config")
        family = task.headers["family"]
        dhash = config_dhash(config)

        # Parse the config using iocextract library
        iocs = parse(family, config)

        if not iocs:
            # Nothing actionable found - skip the config
            return

        # Upload structured data to MISP
        event = MISPEvent()
        event.uuid = str(uuid5(self.CONFIG_NAMESPACE, dhash))
        event.add_tag(f"mwdb:family:{family}")
        event.info = f"Malware configuration ({family})"

        if self.mwdb_url is not None:
            event.add_attribute("link", f"{self.mwdb_url}/config/{dhash}")

        for o in iocs.to_misp():
            event.add_object(o)

        misp = ExpandedPyMISP(self.misp_url, self.misp_key, self.misp_verifycert)
        misp.add_event(event)

    def __init__(
        self,
        config: Config,
        misp_url: str,
        misp_key: str,
        misp_verifycert: bool = True,
        mwdb_url: str = None,
    ) -> None:
        """
        Create instance of the MispPusher.

        :param config: Karton configuration object
        :param misp_url: URL of the paired MISP instance
        :param misp_key: API key of the paired MISP instance
        :param misp_verifycert: "False" to skip TLS cert validation (unrecommended)
        :param mwdb_url: Optional mwdb url, for `link` MISP attribute
        """

        super().__init__(config)

        self.misp_url = misp_url
        self.misp_key = misp_key
        self.misp_verifycert = misp_verifycert
        self.mwdb_url = mwdb_url

    @classmethod
    def args_parser(cls):
        def http_url(value):
            """Ensure that provided value looks like a HTTP URL (https://sth),
            and strip a trailing slash. The goal is to avoid confusion between
            "url.com", "http://url.com", "http://url.com/", etc.
            """
            if not value.startswith("http"):
                raise ValueError("URL should start with http[s]://")
            return value.rstrip("/")

        parser = super().args_parser()
        parser.add_argument(
            "--misp-url",
            type=http_url,
            required=True,
            help="URL of the paired MISP instance",
        )
        parser.add_argument(
            "--misp-key",
            required=True,
            help="API key of the paired MISP instance",
        )
        parser.add_argument(
            "--misp-insecure",
            help="Skip MISP certificate verification",
            action="store_true",
        )
        parser.add_argument(
            "--mwdb-url",
            type=http_url,
            help="Optional mwdb url, for `link` MISP attributes",
        )
        return parser

    @classmethod
    def main(cls):
        parser = cls.args_parser()
        args = parser.parse_args()

        config = Config(args.config_file)
        service = cls(
            config, args.misp_url, args.misp_key, not args.misp_insecure, args.mwdb_url
        )
        service.loop()
