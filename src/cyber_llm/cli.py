"""
Command-line interface for the cyber_llm framework.

This module provides a CLI for testing LLM security mechanisms.
"""

import click
import json
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from cyber_llm.attacks.prompt_injection import PromptInjection, get_example_attacks
from cyber_llm.defenses.input_sanitization import InputSanitizer, SanitizationLevel
from cyber_llm.utils.config import get_config

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """🔐 Cyber LLM Framework - Command Line Interface
    
    Educational tool for testing LLM security vulnerabilities and defenses.
    """
    pass


@cli.command()
@click.option('--prompt', '-p', help='Prompt to test')
@click.option('--file', '-f', type=click.File('r'), help='File containing prompts to test')
@click.option('--level', '-l', type=click.Choice(['basic', 'moderate', 'strict', 'paranoid']), 
              default='moderate', help='Sanitization level')
@click.option('--output', '-o', type=click.File('w'), help='Output file for results')
@click.option('--format', type=click.Choice(['text', 'json']), default='text', help='Output format')
def test(prompt, file, level, output, format):
    """Test prompts for security vulnerabilities."""
    
    # Initialize components
    injection_tester = PromptInjection()
    sanitizer = InputSanitizer(SanitizationLevel(level))
    
    prompts = []
    if prompt:
        prompts.append(prompt)
    elif file:
        prompts.extend(line.strip() for line in file if line.strip())
    else:
        click.echo("Please provide either --prompt or --file option")
        return
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Testing prompts...", total=len(prompts))
        
        for i, test_prompt in enumerate(prompts):
            progress.update(task, description=f"Testing prompt {i+1}/{len(prompts)}")
            
            start_time = time.time()
            
            # Analyze vulnerabilities
            analysis = injection_tester.analyze_vulnerability(test_prompt)
            
            # Sanitize input
            sanitization_result = sanitizer.sanitize(test_prompt)
            
            processing_time = time.time() - start_time
            
            result = {
                'prompt': test_prompt,
                'analysis': analysis,
                'sanitization': {
                    'original_input': sanitization_result.original_input,
                    'sanitized_input': sanitization_result.sanitized_input,
                    'blocked_patterns': sanitization_result.blocked_patterns,
                    'risk_score': sanitization_result.risk_score,
                    'action_taken': sanitization_result.action_taken,
                    'recommendations': sanitization_result.recommendations
                },
                'processing_time_ms': processing_time * 1000
            }
            
            results.append(result)
            progress.advance(task)
    
    # Output results
    if format == 'json':
        output_data = json.dumps(results, indent=2)
        if output:
            output.write(output_data)
        else:
            click.echo(output_data)
    else:
        # Text format
        if output:
            # Redirect console output to file
            with console.capture() as capture:
                _display_results(results, level)
            output.write(capture.get())
        else:
            _display_results(results, level)


@cli.command()
def examples():
    """Show example attack prompts for testing."""
    
    examples = get_example_attacks()
    
    console.print(Panel.fit("🔐 Example Attack Prompts", style="bold blue"))
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Difficulty", style="yellow")
    table.add_column("Prompt", style="white")
    table.add_column("Description", style="green")
    
    for example in examples:
        table.add_row(
            example["name"],
            example["difficulty"],
            example["prompt"][:50] + "..." if len(example["prompt"]) > 50 else example["prompt"],
            example["description"]
        )
    
    console.print(table)
    
    console.print("\\n💡 Use these examples with: cyber-llm test --prompt 'EXAMPLE_PROMPT_HERE'")


@cli.command()
@click.option('--level', '-l', type=click.Choice(['basic', 'moderate', 'strict', 'paranoid']), 
              default='moderate', help='Sanitization level to benchmark')
@click.option('--count', '-c', default=10, help='Number of test prompts to use')
def benchmark(level, count):
    """Benchmark sanitization performance."""
    
    injection_tester = PromptInjection()
    sanitizer = InputSanitizer(SanitizationLevel(level))
    
    # Get test payloads
    payloads = injection_tester.get_test_payloads()
    test_prompts = [payload.content for payload in payloads[:count]]
    
    # Add some safe prompts
    safe_prompts = [
        "Hello, how are you today?",
        "What is the weather like?",
        "Can you help me with my homework?",
        "Tell me a joke",
        "What is 2 + 2?"
    ]
    test_prompts.extend(safe_prompts[:count//2])
    
    console.print(f"🚀 Benchmarking {level} sanitization level with {len(test_prompts)} prompts")
    
    total_time = 0
    detections = 0
    blocks = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Benchmarking...", total=len(test_prompts))
        
        for prompt in test_prompts:
            start_time = time.time()
            result = sanitizer.sanitize(prompt)
            processing_time = time.time() - start_time
            
            total_time += processing_time
            
            if result.risk_score > 0:
                detections += 1
            if result.action_taken in ['sanitized', 'blocked']:
                blocks += 1
            
            progress.advance(task)
    
    # Display results
    avg_time = total_time / len(test_prompts) * 1000  # Convert to ms
    
    table = Table(title=f"Benchmark Results - {level.title()} Level")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Total Prompts", str(len(test_prompts)))
    table.add_row("Detections", f"{detections} ({detections/len(test_prompts)*100:.1f}%)")
    table.add_row("Blocks/Sanitizations", f"{blocks} ({blocks/len(test_prompts)*100:.1f}%)")
    table.add_row("Average Processing Time", f"{avg_time:.2f} ms")
    table.add_row("Total Processing Time", f"{total_time*1000:.2f} ms")
    table.add_row("Throughput", f"{len(test_prompts)/total_time:.1f} prompts/sec")
    
    console.print(table)


@cli.command()
def config():
    """Show current configuration."""
    
    config_obj = get_config()
    config_dict = config_obj.to_dict()
    
    console.print(Panel.fit("🔧 Current Configuration", style="bold blue"))
    
    # Security settings
    security_table = Table(title="Security Settings")
    security_table.add_column("Setting", style="cyan")
    security_table.add_column("Value", style="yellow")
    
    for key, value in config_dict['security'].items():
        security_table.add_row(key, str(value))
    
    console.print(security_table)
    
    # API settings
    api_table = Table(title="API Settings")
    api_table.add_column("Setting", style="cyan")
    api_table.add_column("Value", style="yellow")
    
    for key, value in config_dict['api'].items():
        api_table.add_row(key, str(value))
    
    console.print(api_table)


@cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload')
def serve(host, port, reload):
    """Start the API server."""
    import uvicorn
    
    console.print(f"🚀 Starting Cyber LLM API server on {host}:{port}")
    console.print(f"📖 API documentation available at: http://{host}:{port}/docs")
    
    uvicorn.run(
        "cyber_llm.server:app",
        host=host,
        port=port,
        reload=reload
    )


def _display_results(results, level):
    """Display test results in a formatted way."""
    
    console.print(Panel.fit(f"🔐 Security Test Results - {level.title()} Level", style="bold blue"))
    
    for i, result in enumerate(results, 1):
        console.print(f"\\n📝 Test {i}")
        console.print(f"Prompt: {result['prompt']}")
        
        # Vulnerability analysis
        analysis = result['analysis']
        console.print(f"🔍 Risk Level: {analysis['overall_risk']}")
        console.print(f"🚨 Vulnerabilities: {len(analysis['vulnerabilities'])}")
        
        if analysis['vulnerabilities']:
            for vuln in analysis['vulnerabilities']:
                console.print(f"   • {vuln['type']} (risk: {vuln['risk']})")
        
        # Sanitization results
        sanitization = result['sanitization']
        console.print(f"🛡️  Sanitized: {sanitization['sanitized_input']}")
        console.print(f"📊 Risk Score: {sanitization['risk_score']:.2f}")
        console.print(f"⚡ Action: {sanitization['action_taken']}")
        
        if sanitization['blocked_patterns']:
            console.print("🚫 Blocked Patterns:")
            for pattern in sanitization['blocked_patterns']:
                console.print(f"   • {pattern}")
        
        if sanitization['recommendations']:
            console.print("💡 Recommendations:")
            for rec in sanitization['recommendations']:
                console.print(f"   • {rec}")
        
        console.print(f"⏱️  Processing Time: {result['processing_time_ms']:.2f} ms")
    
    # Summary
    if len(results) > 1:
        avg_risk = sum(r['sanitization']['risk_score'] for r in results) / len(results)
        high_risk_count = sum(1 for r in results if r['sanitization']['risk_score'] > 1.0)
        
        console.print(f"\\n📈 Summary:")
        console.print(f"   Total Tests: {len(results)}")
        console.print(f"   Average Risk Score: {avg_risk:.2f}")
        console.print(f"   High Risk Prompts: {high_risk_count}")


def main():
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()