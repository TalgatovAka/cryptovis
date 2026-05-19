import sys

from crypto_pipeline import build_default_elements, run_crypto_pipeline


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass

    elements = build_default_elements()
    results = run_crypto_pipeline(elements)

    print('=== Crypto pipeline console output ===')
    print('1. Validation')
    for message in results['validator_messages']:
        print(f'- {message}')

    print('\n2. Security audit')
    for issue in results['audit_issues']:
        print(f'- {issue}')

    print('\n3. Export JSON')
    print(results['export_json'])

    print('\n4. PKI report')
    print(results['pki_report'])


if __name__ == '__main__':
    main()
