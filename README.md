# karton-misp-pusher

Listens for new samples in the [karton](https://karton-core.readthedocs.io/en/latest/)
pipeline and uploads them to MISP.

Configs are parsed using the [mwdb-iocextract](https://github.com/CERT-Polska/mwdb_iocextract)
project. This means, that we operate on a higher level than raw JSON configs, and makes
it possible to correlate different samples and campaigns (for example, by the used crypto
material).

**Author**: CERT.pl

**Maintainers**: nazywam

**Consumes:**
```
{
    "type": "config",
}
```

**Result:**

![config in misp](./docs/misp.png)

## Usage

First of all, make sure you have setup the core system: https://github.com/CERT-Polska/karton.
[More info here](https://github.com/CERT-Polska/karton/blob/master/docs/how-to-run.md).

Then install karton-misp-pusher from PyPi:

```shell
$ pip install karton-misp-pusher

$ karton-misp-pusher --misp-url https://misp.url --misp-key SECRET123
```

You can also add optional xrefs to mwdb with `--mwdb-url`, or skip MISP
verification with `--misp-insecure`. For more options see `--help`.

## Adding Galaxy clusters relationship

It's possible to link new events to existing MISP Galaxy clusters using a mapping file.

The mapping file is a simple JSON document that assings a cluster UUID for each malware family in your ecosystem.

An example using the [Malpedia MISP Galaxy would be](https://malpedia.caad.fkie.fraunhofer.de/usage/api#/api/get/misp):
```json
{
    "404keylogger": "6b87fada-86b3-449d-826d-a89858121b68",
    "agenttesla": "b88e29cf-79d9-42bc-b369-0383b5e04380",
    "amadey": "77f2c81f-be07-475a-8d77-f59b4847f696"
}
```

With that ready you can then launch the karton service with the `--galaxy-clusters-mapping` argument pointing to the file.


![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/uploads/2019/02/en_horizontal_cef_logo-e1550495232540.png)
