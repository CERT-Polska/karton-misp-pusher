from karton.core import Karton, Task, Config
from mwdb_iocextract import parse  # type: ignore
from mwdblib.util import config_dhash  # type: ignore
from pymisp import ExpandedPyMISP, MISPEvent
from uuid import UUID, uuid5


class MispPusher(Karton):
    """
    Transforms configurations using mwdb-iocextract and pushes to misp.cert.pl
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

        event.add_attribute("link", f"https://mwdb.cert.pl/config/{dhash}")

        for o in iocs.to_misp():
            event.add_object(o)

        misp = ExpandedPyMISP(self.misp_url, self.misp_key, self.misp_verifycert)
        misp.add_event(event)

    def __init__(
        self,
        config: Config,
        misp_url: str,
        misp_key: str,
        misp_verifycert: bool = True
    ) -> None:
        """
        Create instance of the MispPusher.

        :param config: Karton configuration object
        :param misp_url: URL of the paired MISP instance
        :param misp_key: API key of the paired MISP instance
        :param misp_verifycert: "False" to skip TLS cert validation (unrecommended)
        """

        super().__init__(config)

        self.misp_url = misp_url
        self.misp_key = misp_key
        self.misp_verifycert = misp_verifycert

    @classmethod
    def args_parser(cls):
        parser = super().args_parser()
        parser.add_argument(
            "--misp-url",
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
            action="store_true"
        )
        return parser

    @classmethod
    def main(cls):
        parser = cls.args_parser()
        args = parser.parse_args()

        config = Config(args.config_file)
        service = cls(
            config, args.misp_url, args.misp_key, not args.misp_insecure
        )
        service.loop()
