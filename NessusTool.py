import click
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


@click.group()
def cli():
    pass


@cli.command()
@click.option("--host", "-t", default="localhost", help="Host to scan")
@click.option("--api-key", "-k", default=None, help="API Key for Nessus")
@click.option("--secret", "-s", default=None, help="Secret for Nessus")
@click.option("--policy-id", "-p", default=None, help="Nessus Policy ID")
@click.option("--ignore-ssl", "-i", is_flag=True, help="Ignore SSL errors")
@click.option("--remote-host", "-r", default=None, help="Remote host endpoint")
def create_scan(host, api_key, secret, policy_id, ignore_ssl, remote_host):
    try:
        if remote_host:
            url = "https://" + remote_host + ":8834/scans"
        else:
            url = "https://localhost:8834/scans"
        if not policy_id:
            policy_id = click.prompt("Enter Nessus Policy ID")
        data = {
            "uuid": policy_id,
            "settings": {"name": "My Scan", "text_targets": host},
        }
        headers = {
            "Content-type": "application/json",
            "X-ApiKeys": "accessKey=" + api_key + "; secretKey=" + secret,
        }

        # Add debug prints
        # print(f"url: {url}")
        # print(f"headers: {headers}")
        # print(f"data: {data}")

        if ignore_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            response = requests.post(url, headers=headers, json=data, verify=False)
        else:
            response = requests.post(url, headers=headers, json=data)
        if response.status_code == 201:
            click.echo("Scan created")
        else:
            click.echo("Error creating scan: " + response.text)
    except requests.exceptions.RequestException as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option("--api-key", "-k", default=None, help="API Key for Nessus")
@click.option("--secret", "-s", default=None, help="Secret for Nessus")
@click.option("--ignore-ssl", "-i", is_flag=True, help="Ignore SSL errors")
@click.option("--remote-host", "-r", default=None, help="Remote host endpoint")
def list_policies(api_key, secret, ignore_ssl, remote_host):
    try:
        if remote_host:
            url = "https://" + remote_host + ":8834/policies"
        else:
            url = "https://localhost:8834/policies"
        headers = {
            "Content-type": "application/json",
            "X-ApiKeys": "accessKey=" + api_key + "; secretKey=" + secret,
        }
        if ignore_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            response = requests.get(url, headers=headers, verify=False)
        else:
            response = requests.get(url, headers=headers)
        if response.status_code == 200:
            policies = json.loads(response.text)
            click.echo("Available policies:")
            for policy in policies["policies"]:
                click.echo(f"{policy['name']} - ID: {policy['id']}")
        else:
            click.echo("Error listing policies: " + response.text)
    except requests.exceptions.RequestException as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option("--api-key", "-k", default=None, help="API Key for Nessus")
@click.option("--secret", "-s", default=None, help="Secret for Nessus")
@click.option("--ignore-ssl", "-i", is_flag=True, help="Ignore SSL errors")
@click.option("--remote-host", "-r", default=None, help="Remote host endpoint")
@click.option("--report-name", "-n", default=None, help="Name for the report")
def get_reports(api_key, secret, ignore_ssl, remote_host, report_name):
    try:
        if remote_host:
            url = "https://" + remote_host + ":8834/scans"
        else:
            url = "https://localhost:8834/scans"
        headers = {
            "Content-type": "application/json",
            "X-ApiKeys": "accessKey=" + api_key + "; secretKey=" + secret,
        }
        response = requests.get(url, headers=headers, verify=not ignore_ssl)
        if response.status_code == 200:
            reports = json.loads(response.text)
            click.echo("Available reports:")
            for i, report in enumerate(reports["scans"]):
                click.echo(
                    f"{i+1}. {report['name']} - ID: {report['id']} - Status: {report['status']}"
                )
            report_idx = click.prompt(
                "Enter the number of the report you want to download", type=int
            )
            if reports["scans"][report_idx - 1]["status"] != "completed":
                click.echo(f"Error: Report {report_idx} is not completed yet.")
                return
            report_id = reports["scans"][report_idx - 1]["id"]
            download_url = f"https://{remote_host}:8834/scans/{report_id}/export"
            report_response = requests.post(
                download_url,
                headers=headers,
                json={"format": "nessus"},
                verify=not ignore_ssl,
            )
            if report_response.status_code == 200:
                if report_name:
                    report_file = report_name
                else:
                    report_file = f"report_{report_id}.nessus"
                with open(report_file, "wb") as f:
                    f.write(report_response.content)
                click.echo(f"Report {report_id} saved to {report_file}")
            else:
                click.echo(f"Error downloading report: {report_response.text}")
        else:
            click.echo(f"Error listing reports: {response.text}")
    except requests.exceptions.RequestException as e:
        click.echo(f"Error: {str(e)}")


if __name__ == "__main__":
    cli()