# Resource use in p2soc 1.4.0

With four local WebKit dashboards, the Rust host used **14.3% less host RSS**
and its full browser process tree used **5.9% less PSS** than the Python
compatibility host. Idle CPU use was under 1% of one core for both
implementations. Startup times varied across runs.

| Metric | Rust median | Python median | Observed change |
|---|---:|---:|---:|
| Time to load all four authenticated dashboards | 2.72 s | 2.91 s | 0.19 s earlier |
| Host idle RSS | 200.3 MiB | 233.8 MiB | 33.5 MiB lower |
| Wall and browser idle PSS | 325.4 MiB | 346.0 MiB | 20.5 MiB lower |
| Peak sampled sum of process RSS | 1,139.7 MiB | 1,172.4 MiB | 32.6 MiB lower |
| Host idle CPU, percentage of one core | 0.10% | 0.10% | <0.01 percentage points |
| Wall and browser idle CPU, percentage of one core | 0.50% | 0.60% | 0.10 percentage points lower |

The RSS sum counts shared pages for each process. Use PSS to estimate how much
physical memory the process tree accounts for. Startup ranged from 2.30 to
4.06 s in Rust and 2.24 to 3.67 s in Python. These intervals overlap, as do the
idle CPU ranges.

## Method

Measured on 2026-11-23 on an x86-64 Intel Core i5-1235U with 23 GiB of visible
RAM, Kali Linux 7.1.5, GTK 3.24.52 and WebKitGTK 2.52.6. The comparison ran
the optimized Rust 1.4.0 binary and the shipped Python compatibility host on
Python 3.14.8. Each implementation ran five times, alternating which started
first. Each trial used a fresh isolated profile and the same four local login
forms and static dashboards in a 1280×720 Xvfb display. Both hosts used the dev
vault fixture, a 0.5 s launch stagger and software rendering.

Startup ends when the fixture serves the last authenticated dashboard.
The sampler waits five seconds after that event, then reads Linux
`/proc` memory and CPU counters over ten seconds. The table reports the
median of the five per-trial results. The wall tree includes its browser
descendants. The server fixture and Xvfb are outside that tree.

Reproduce from a source checkout with the Python runtime dependencies
listed in [Development](DEVELOPMENT.md):

```sh
make rust-release
xvfb-run -a -s '-screen 0 1280x720x24' python3 dev/benchmark.py \
  --runs 5 --idle 10 --settle 5 > wall-benchmark.json
```

The script emits summary medians and all trials as JSON. Use
`--python .venv/bin/python` to select a Python installation with PyGObject.

## On-device validation

The comparison covers a static dashboard workload on x86-64. Raspberry Pi boot,
long-running memory pressure, Chromium resource use, the compositor, Vaultwarden,
VPN and production dashboards require separate measurements. Complete the
[installation checklist](INSTALL.md#bring-up-checklist) on the intended device
with the real panels connected.
