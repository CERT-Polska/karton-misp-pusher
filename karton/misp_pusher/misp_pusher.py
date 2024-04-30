import argparse
import json
from uuid import UUID, uuid5

from karton.core import Config, Karton, Task
from mwdb_iocextract import parse  # type: ignore
from mwdblib.util import config_dhash  # type: ignore
from pymisp import MISPEvent, PyMISP
from pymisp.mispevent import MISPGalaxyCluster


def http_url(value: str) -> str:
    """Ensure that provided value looks like a HTTP URL (https://sth),
    and strip a trailing slash. The goal is to avoid confusion between
    "url.com", "http://url.com", "http://url.com/", etc.
    """
    if not value.startswith("http"):
        raise ValueError("URL should start with http[s]://")
    return value.rstrip("/")


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

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        if not self.config.get("misp", "url"):
            raise RuntimeError("Misp config section is missing the url parameter")

        if not self.config.get("misp", "key"):
            raise RuntimeError("Misp config section is missing the key parameter")

        self.misp_url = http_url(self.config.get("misp", "url"))
        self.misp_key = self.config.get("misp", "key")
        self.misp_ssl = not self.config.getboolean("misp", "insecure", False)
        self.misp_timeout = self.config.getint("misp", "timeout", 10)
        self.tag_events = self.config.getboolean("misp", "tag_events", True)
        self.misp_published = self.config.getboolean("misp", "published", False)

        self.cluster_mapping = {}
        if self.config.get("misp", "galaxy_clusters_mapping"):
            with open(self.config.get("misp", "galaxy_clusters_mapping"), "r") as f:
                self.cluster_mapping = json.load(f)
                self.log.info(
                    "Loaded MISP cluster mappings for %d families",
                    len(self.cluster_mapping.keys()),
                )

    def process(self, task: Task) -> None:
        config = task.get_payload("config")
        family = task.headers["family"]
        dhash = config_dhash(config)

        # Parse the config using iocextract library
        iocs = parse(family, config)

        if not iocs:
            # Nothing actionable found - skip the config
            return

        misp = PyMISP(
            url=self.misp_url,
            key=self.misp_key,
            ssl=self.misp_ssl,
            timeout=self.misp_timeout,
        )

        # Upload structured data to MISP
        event = MISPEvent()
        event.uuid = str(uuid5(self.CONFIG_NAMESPACE, dhash))

        event.add_tag("mwdb:static")

        if self.tag_events:
            event.add_tag(f"mwdb:family:{family}")

        if self.cluster_mapping:
            if family not in self.cluster_mapping:
                self.log.error(
                    "Family name %s not present in MISP cluster mapping", family
                )
            else:
                cluster_uuid = self.cluster_mapping[family]
                if cluster_uuid is None:
                    self.log.info(
                        "Family %s ignored in cluster mapping, not reporting it", family
                    )
                    return

                galaxy_cluster = misp.get_galaxy_cluster(cluster_uuid, pythonify=True)
                if type(galaxy_cluster) is not MISPGalaxyCluster:
                    raise Exception(
                        f"Couldn't find galaxy cluster: {str(galaxy_cluster)}"
                    )

                self.log.info(
                    "Adding tag %s for cluster relationship",
                    galaxy_cluster.tag_name,  # type: ignore
                )
                event.add_tag(galaxy_cluster.tag_name)  # type: ignore

        event.info = f"Malware configuration ({family})"

        mwdb_url = self.config.get("misp", "mwdb_url")

        if mwdb_url is not None:
            event.add_attribute("link", f"{mwdb_url}/config/{dhash}")

        for o in iocs.to_misp():
            event.add_object(o)

        event.published = self.misp_published

        misp.add_event(event)

    @classmethod
    def args_parser(cls) -> argparse.ArgumentParser:
        parser = super().args_parser()
        parser.add_argument(
            "--misp-url",
            help="URL of the paired MISP instance",
        )
        parser.add_argument(
            "--misp-key",
            help="API key of the paired MISP instance",
        )
        parser.add_argument(
            "--misp-published",
            action="store_true",
            help="Publish MISP Events",
            default=None,
        )
        parser.add_argument(
            "--misp-tag-events",
            help="Tag MISP events with mwdb family names",
            action=argparse.BooleanOptionalAction,
            default=None,
        )
        parser.add_argument(
            "--misp-insecure",
            help="Skip MISP certificate verification",
            action="store_true",
            default=None,
        )
        parser.add_argument(
            "--mwdb-url",
            type=http_url,
            help="Optional mwdb url, for `link` MISP attributes",
        )
        parser.add_argument(
            "--galaxy-clusters-mapping",
            help="Link config family names to galaxy clusters using the file",
        )
        return parser

    @classmethod
    def config_from_args(cls, config: Config, args: argparse.Namespace) -> None:
        super().config_from_args(config, args)
        config.load_from_dict(
            {
                "misp": {
                    "url": args.misp_url,
                    "key": args.misp_key,
                    "published": args.misp_published,
                    "tag_events": args.misp_tag_events,
                    "insecure": args.misp_insecure,
                    "mwdb_url": args.mwdb_url,
                    "galaxy_clusters_mapping": args.galaxy_clusters_mapping,
                }
            }
        )
