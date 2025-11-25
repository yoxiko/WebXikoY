import click
import asyncio
import json
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import ScanEngine
from core.config import ConfigManager
from reporting.generator import ReportGenerator

@click.group()
@click.option('--config', default='config/webxikoy.yaml', help='Config file path')
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    ctx.obj['config'] = ConfigManager()
    ctx.obj['engine'] = ScanEngine()
    ctx.obj['reporter'] = ReportGenerator(ctx.obj['config'])

@cli.command()
@click.argument('targets', nargs=-1)
@click.option('--profile', default='default', help='Scan profile')
@click.option('--output', default='report', help='Output file prefix')
@click.option('--format', 'output_format', type=click.Choice(['html', 'pdf', 'json']), default='html')
@click.pass_context
def scan(ctx, targets, profile, output, output_format):
    """Scan network targets for vulnerabilities"""
    if not targets:
        click.echo("Error: No targets specified")
        return
    
    async def run_scan():
        await ctx.obj['engine'].initialize()
        try:
            results = await ctx.obj['engine'].scan_network(list(targets), profile)
            
            for result in results:
                report_data = {
                    'services': result.services,
                    'vulnerabilities': result.vulnerabilities,
                    'cves': result.cves
                }
                
                if output_format == 'html':
                    report_content = await ctx.obj['reporter'].generate_html_report(report_data, result.target)
                    filename = f"{output}_{result.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                    with open(filename, 'w') as f:
                        f.write(report_content)
                
                elif output_format == 'pdf':
                    report_content = await ctx.obj['reporter'].generate_pdf_report(report_data, result.target)
                    filename = f"{output}_{result.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                    with open(filename, 'wb') as f:
                        f.write(report_content)
                
                elif output_format == 'json':
                    report_content = await ctx.obj['reporter'].generate_json_report(report_data, result.target)
                    filename = f"{output}_{result.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(filename, 'w') as f:
                        f.write(report_content)
                
                click.echo(f"Report saved: {filename}")
                
        finally:
            await ctx.obj['engine'].shutdown()
    
    asyncio.run(run_scan())

@cli.command()
@click.argument('cve_id')
@click.pass_context
def cve_info(ctx, cve_id):
    """Get detailed information about a CVE"""
    cve_details = ctx.obj['engine']._analyze_cves.__self__.cve_manager.get_cve_details(cve_id)
    
    if cve_details:
        click.echo(f"CVE: {cve_details['id']}")
        click.echo(f"Severity: {cve_details['severity']}")
        click.echo(f"CVSS Score: {cve_details['cvss_score']}")
        click.echo(f"Description: {cve_details['description']}")
        click.echo(f"Published: {cve_details['published_date']}")
    else:
        click.echo("CVE not found")

@cli.command()
@click.option('--product', help='Product name')
@click.option('--version', help='Product version')
@click.pass_context
def cve_search(ctx, product, version):
    """Search for CVEs by product and version"""
    if product and version:
        cves = ctx.obj['engine']._analyze_cves.__self__.cve_manager.get_cves_for_service(product, version)
        for cve in cves:
            click.echo(f"{cve['id']} - {cve['severity']} - CVSS: {cve['cvss_score']}")
    else:
        click.echo("Please specify --product and --version")

@cli.command()
@click.pass_context
def stats(ctx):
    """Show CVE database statistics"""
    stats_data = ctx.obj['engine']._analyze_cves.__self__.cve_manager.get_statistics()
    click.echo(f"Total CVEs: {stats_data['total_cves']}")
    click.echo(f"Average CVSS: {stats_data['average_cvss']}")
    click.echo("Severity Distribution:")
    for severity, count in stats_data['severity_distribution'].items():
        click.echo(f"  {severity}: {count}")

@cli.command()
@click.pass_context
def sync(ctx):
    """Sync CVE database with NVD"""
    async def run_sync():
        await ctx.obj['engine']._analyze_cves.__self__.cve_manager.initialize()
        click.echo("CVE database synced successfully")
    
    asyncio.run(run_sync())

@cli.command()
@click.argument('target')
@click.option('--ports', default='1-1000', help='Port range to scan')
@click.pass_context
def portscan(ctx, target, ports):
    """Perform port scan on target"""
    from scanners.network.port_scanner import PortScanner
    
    async def run_portscan():
        scanner = PortScanner(ctx.obj['config'])
        open_ports = await scanner.scapy_scan(target)
        
        click.echo(f"Open ports on {target}:")
        for port in open_ports:
            click.echo(f"  {port}/tcp")
    
    asyncio.run(run_portscan())

if __name__ == '__main__':
    cli()