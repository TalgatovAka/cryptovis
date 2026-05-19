import abc
import dataclasses
import json
from datetime import date
from typing import Any, Dict, List

class CryptoVisitor(abc.ABC):
    @abc.abstractmethod
    def visit_x509(self, cert: 'X509Certificate') -> None:
        pass

    @abc.abstractmethod
    def visit_signature(self, sig: 'DetachedSignature') -> None:
        pass

    @abc.abstractmethod
    def visit_container(self, container: 'KeyContainer') -> None:
        pass

class CryptoElement(abc.ABC):
    @abc.abstractmethod
    def accept(self, visitor: CryptoVisitor) -> None:
        pass

@dataclasses.dataclass
class X509Certificate(CryptoElement):
    serial_number: str
    subject_name: str
    not_after: date
    algorithm: str

    def accept(self, visitor: CryptoVisitor) -> None:
        visitor.visit_x509(self)

@dataclasses.dataclass
class DetachedSignature(CryptoElement):
    document_hash: bytes
    signature: bytes
    hash_algorithm: str

    def accept(self, visitor: CryptoVisitor) -> None:
        visitor.visit_signature(self)

@dataclasses.dataclass
class KeyContainer(CryptoElement):
    container_name: str
    protection_level: str
    storage_type: str

    def accept(self, visitor: CryptoVisitor) -> None:
        visitor.visit_container(self)

class CryptoValidator(CryptoVisitor):
    def __init__(self) -> None:
        self.messages: List[str] = []

    def visit_x509(self, cert: X509Certificate) -> None:
        if cert.not_after < date.today():
            self.messages.append(f"Certificate '{cert.subject_name}' expired on {cert.not_after}.")
        else:
            self.messages.append(f"Certificate '{cert.subject_name}' is valid until {cert.not_after}.")

    def visit_signature(self, sig: DetachedSignature) -> None:
        if len(sig.document_hash) < 32:
            self.messages.append(f"Signature hash is too short ({len(sig.document_hash)} bytes).")
        else:
            self.messages.append(f"Signature hash length is sufficient ({len(sig.document_hash)} bytes).")

    def visit_container(self, container: KeyContainer) -> None:
        if container.protection_level.lower() == 'exportable':
            self.messages.append(f"Container '{container.container_name}' is not securely protected.")
        else:
            self.messages.append(f"Container '{container.container_name}' is protected.")

class ExportJsonVisitor(CryptoVisitor):
    def __init__(self) -> None:
        self.elements: List[dict] = []

    def visit_x509(self, cert: X509Certificate) -> None:
        self.elements.append({
            'type': 'X509Certificate',
            'serial_number': cert.serial_number,
            'subject_name': cert.subject_name,
            'not_after': cert.not_after.isoformat(),
            'algorithm': cert.algorithm,
        })

    def visit_signature(self, sig: DetachedSignature) -> None:
        self.elements.append({
            'type': 'DetachedSignature',
            'document_hash': sig.document_hash.hex(),
            'signature': sig.signature.hex(),
            'hash_algorithm': sig.hash_algorithm,
        })

    def visit_container(self, container: KeyContainer) -> None:
        self.elements.append({
            'type': 'KeyContainer',
            'container_name': container.container_name,
            'protection_level': container.protection_level,
            'storage_type': container.storage_type,
        })

    def export(self) -> str:
        return json.dumps(self.elements, indent=2, ensure_ascii=False)

class SecurityAuditor(CryptoVisitor):
    deprecated_algorithms = {'MD5', 'SHA1'}

    def __init__(self) -> None:
        self.issues: List[str] = []

    def visit_x509(self, cert: X509Certificate) -> None:
        if cert.algorithm.upper() in self.deprecated_algorithms:
            self.issues.append(f"Certificate '{cert.subject_name}' uses deprecated algorithm {cert.algorithm}.")
        else:
            self.issues.append(f"Certificate '{cert.subject_name}' algorithm {cert.algorithm} is acceptable.")

    def visit_signature(self, sig: DetachedSignature) -> None:
        self.issues.append(f"Signature hash algorithm {sig.hash_algorithm} was checked.")

    def visit_container(self, container: KeyContainer) -> None:
        if container.storage_type.lower() != 'smartcard':
            self.issues.append(f"Container '{container.container_name}' is stored on less secure media ({container.storage_type}).")
        else:
            self.issues.append(f"Container '{container.container_name}' storage type {container.storage_type} is secure.")

class PkiReportGenerator(CryptoVisitor):
    def __init__(self) -> None:
        self.total_objects = 0
        self.expired_certificates = 0
        self.deprecated_algorithms = 0
        self.weak_containers = 0
        self.short_hashes = 0

    def visit_x509(self, cert: X509Certificate) -> None:
        self.total_objects += 1
        if cert.not_after < date.today():
            self.expired_certificates += 1
        if cert.algorithm.upper() in SecurityAuditor.deprecated_algorithms:
            self.deprecated_algorithms += 1

    def visit_signature(self, sig: DetachedSignature) -> None:
        self.total_objects += 1
        if len(sig.document_hash) < 32:
            self.short_hashes += 1

    def visit_container(self, container: KeyContainer) -> None:
        self.total_objects += 1
        if container.protection_level.lower() == 'exportable' or container.storage_type.lower() != 'smartcard':
            self.weak_containers += 1

    def get_report(self) -> str:
        return (
            f"PKI Report:\n"
            f"  Total objects checked: {self.total_objects}\n"
            f"  Expired certificates: {self.expired_certificates}\n"
            f"  Deprecated algorithms: {self.deprecated_algorithms}\n"
            f"  Short signature hashes: {self.short_hashes}\n"
            f"  Weak containers: {self.weak_containers}\n"
        )


def build_default_elements() -> List[CryptoElement]:
    return [
        X509Certificate(
            serial_number='1234567890',
            subject_name='ООО «Документ»',
            not_after=date(2027, 12, 31),
            algorithm='GOST_2015',
        ),
        DetachedSignature(
            document_hash=bytes.fromhex('aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899'),
            signature=bytes.fromhex('deadbeefcafebabe'),
            hash_algorithm='SHA256',
        ),
        KeyContainer(
            container_name='UserKeyContainer',
            protection_level='exportable',
            storage_type='Cloud',
        ),
    ]


def run_crypto_pipeline(elements: List[CryptoElement]) -> Dict[str, Any]:
    validator = CryptoValidator()
    auditor = SecurityAuditor()
    exporter = ExportJsonVisitor()
    report_generator = PkiReportGenerator()

    for element in elements:
        element.accept(validator)
        element.accept(auditor)
        element.accept(exporter)
        element.accept(report_generator)

    return {
        'validator_messages': validator.messages,
        'audit_issues': auditor.issues,
        'export_json': exporter.export(),
        'pki_report': report_generator.get_report(),
    }
