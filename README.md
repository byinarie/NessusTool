
<h1 align="center">
  <br>
NessusTool
  <br>
</h1>

<h4 align="center">Python wrapper for the Nessus API to automate common tasks.</h4>

<p align="center">
  <a href="#install">Install</a> •
  <a href="#examples">Examples</a> •
  <a href="#related">Related</a> •
  <a href="#license">License</a>
</p>

## Install
```bash
git clone https://github.com/byinarie/NessusTool.git
pip3 install -r requirements.txt 
```

## Examples

* Create a scan — Requires [Nessus Manager](https://www.tenable.com/sites/drupal.dmz.tenablesecurity.com/files/datasheets/NessusManager-(DS)-EN-v4_0.pdf)
```python
python3 NessusTool.py create-scan --api-key KEY --secret SECRET --remote-host HOSTNAME
```
* List policies
```python
python3 NessusTool.py list-policies --api-key KEY --secret SECRET --remote-host HOSTNAME
```
* Export scan results
```python
python3 NessusTool.py get-reports --api-key KEY --secret SECRET --remote-host HOSTNAME
```
## Related 
* https://localhost:8834/api#/
* https://localhost:8834/api#/resources/scans/configure
## License

MIT

---

