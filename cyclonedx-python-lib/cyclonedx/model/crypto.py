from enum import Enum
from typing import Iterable, Optional, Any

# See https://github.com/package-url/packageurl-python/issues/65
import serializable
from sortedcontainers import SortedSet

from . import ComparableTuple
from ..exception.model import NoPropertiesProvidedException
from ..schema.schema import SchemaVersion1Dot4CbomVersion1Dot0


class AssetType(str, Enum):
    """
    Enum object that defines the permissible 'types' for a crypto asset according to the CBOM schema.

    .. note::
        See the CycloneDX Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L484
    """
    ALGORITHM = 'algorithm'
    CERTIFICATE = 'certificate'
    RELATED_CRYPTO_MATERIAL = 'relatedCryptoMaterial'
    PROTOCOL = 'protocol'


class Primitive(str, Enum):
    """
    Enum object that defines the permissible 'types' for a crypto asset primitive according to the CBOM schema.

    .. note::
        See the CycloneDX Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L501
    """
    AUTHENTICATED_ENCRYPTION = 'ae'
    BLOCK_CIPHER = 'blockcipher'
    DETERMINISTIC_RANDOM_BIT_GENERATOR = 'drbg'
    EXTENDABLE_OUTPUT_FUNCTION = 'xof'
    HASH = 'hash'
    KEY_AGREE = 'keyagree'
    KEY_DERIVATION_FUNCTION = 'kdf'
    KEY_ENCAPSULATION_MECHANISM = 'kem'
    MESSAGE_AUTHENTICATION_CODE = 'mac'
    OTHER = 'other'
    PUBLIC_KEY_ENCRYPTION = 'pke'
    STREAM_CIPHER = 'streamcipher'
    SIGNATURE = 'signature'
    UNKNOWN = 'unknown'


@serializable.serializable_class
class IKEv2TransformTypes:
    """
    Our internal representation of the `ikev2TransformTypes` complex type.

    .. note::
        See the CBOM Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L747
    """

    def __init__(self, *, transform_type_1: Optional[Iterable[str]] = None,
                 transform_type_2: Optional[Iterable[str]] = None, transform_type_3: Optional[Iterable[str]] = None,
                 transform_type_4: Optional[Iterable[str]] = None) -> None:

        self.transform_type_1 = transform_type_1 or []
        self.transform_type_2 = transform_type_2 or []
        self.transform_type_3 = transform_type_3 or []
        self.transform_type_4 = transform_type_4 or []

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'transform')
    def transform_type_1(self) -> "SortedSet[str]":
        return self._transform_type_1

    @transform_type_1.setter
    def transform_type_1(self, transform_type_1: Iterable[str]) -> None:
        self._transform_type_1 = SortedSet(transform_type_1)

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'transform')
    def transform_type_2(self) -> "SortedSet[str]":
        return self._transform_type_2

    @transform_type_2.setter
    def transform_type_2(self, transform_type_2: Iterable[str]) -> None:
        self._transform_type_2 = SortedSet(transform_type_2)

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'transform')
    def transform_type_3(self) -> "SortedSet[str]":
        return self._transform_type_3

    @transform_type_3.setter
    def transform_type_3(self, transform_type_3: Iterable[str]) -> None:
        self._transform_type_3 = SortedSet(transform_type_3)

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'transform')
    def transform_type_4(self) -> "SortedSet[str]":
        return self._transform_type_4

    @transform_type_4.setter
    def transform_type_4(self, transform_type_4: Iterable[str]) -> None:
        self._transform_type_4 = SortedSet(transform_type_4)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, IKEv2TransformTypes):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((
            tuple(self.transform_type_1), tuple(self.transform_type_2), tuple(self.transform_type_3),
            tuple(self.transform_type_4)
        ))


@serializable.serializable_class
class AlgorithmProperties:
    """
    Our internal representation of the `algorithmProperties` complex type.

    .. note::
        See the CBOM Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L495
    """

    def __init__(self, *, primitive: Optional[Primitive] = None, variant: Optional[str] = None,
                 implementation_level: Optional[str] = None, implementation_platform: Optional[str] = None,
                 certification_level: Optional[str] = None, mode: Optional[str] = None, padding: Optional[str] = None,
                 crypto_functions: Optional[Iterable[str]] = None) -> None:
        self.primitive = primitive
        self.variant = variant
        self.implementation_level = implementation_level
        self.implementation_platform = implementation_platform
        self.certification_level = certification_level
        self.mode = mode
        self.padding = padding
        self.crypto_functions = crypto_functions or []  # type: ignore

    @property
    @serializable.xml_attribute()
    def primitive(self) -> Optional[str]:
        return self._primitive

    @primitive.setter
    def primitive(self, primitive: Optional[str]) -> None:
        self._primitive = primitive

    @property
    def variant(self) -> Optional[str]:
        return self._variant

    @variant.setter
    def variant(self, variant: Optional[str]) -> None:
        self._variant = variant

    @property
    def implementation_level(self) -> Optional[str]:
        return self._implementation_level

    @implementation_level.setter
    def implementation_level(self, implementation_level: Optional[str]) -> None:
        self._implementation_level = implementation_level

    @property
    def implementation_platform(self) -> Optional[str]:
        return self._implementation_platform

    @implementation_platform.setter
    def implementation_platform(self, implementation_platform: Optional[str]) -> None:
        self._implementation_platform = implementation_platform

    @property
    def certification_level(self) -> Optional[str]:
        return self._certification_level

    @certification_level.setter
    def certification_level(self, certification_level: Optional[str]) -> None:
        self._certification_level = certification_level

    @property
    def mode(self) -> Optional[str]:
        return self._mode

    @mode.setter
    def mode(self, mode: Optional[str]) -> None:
        self._mode = mode

    @property
    def padding(self) -> Optional[str]:
        return self._padding

    @padding.setter
    def padding(self, padding: Optional[str]) -> None:
        self._padding = padding

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'cryptoFunction')
    def crypto_functions(self) -> "SortedSet[str]":
        return self._crypto_functions

    @crypto_functions.setter
    def crypto_functions(self, crypto_functions: Iterable[str]) -> None:
        self._crypto_functions = SortedSet(crypto_functions)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AlgorithmProperties):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((
            self.primitive, self.variant, self.implementation_level, self.implementation_platform,
            self.certification_level, self.mode, self.padding, tuple(self.crypto_functions)
        ))


@serializable.serializable_class
class CertificateProperties:
    """
    Our internal representation of the `certificateProperties` complex type.

    .. note::
        See the CBOM Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L640
    """

    def __init__(self, *, subject_name: Optional[str] = None, issuer_name: Optional[str] = None,
                 not_valid_before: Optional[str] = None, not_valid_after: Optional[str] = None,
                 certificate_algorithm: Optional[str] = None, certificate_signature_algorithm: Optional[str] = None,
                 certificate_format: Optional[str] = None, certificate_extensions: Optional[str] = None) -> None:
        self.subject_name = subject_name
        self.issuer_name = issuer_name
        self.not_valid_before = not_valid_before
        self.not_valid_after = not_valid_after
        self.certificate_algorithm = certificate_algorithm
        self.certificate_signature_algorithm = certificate_signature_algorithm
        self.certificate_format = certificate_format
        self.certificate_extensions = certificate_extensions

    @property
    def subject_name(self) -> Optional[str]:
        return self._subject_name

    @subject_name.setter
    def subject_name(self, subject_name: Optional[str]) -> None:
        self._subject_name = subject_name

    @property
    def issuer_name(self) -> Optional[str]:
        return self._issuer_name

    @issuer_name.setter
    def issuer_name(self, issuer_name: Optional[str]) -> None:
        self._issuer_name = issuer_name

    @property
    def not_valid_before(self) -> Optional[str]:
        return self._not_valid_before

    @not_valid_before.setter
    def not_valid_before(self, not_valid_before: Optional[str]) -> None:
        self._not_valid_before = not_valid_before

    @property
    def not_valid_after(self) -> Optional[str]:
        return self._not_valid_after

    @not_valid_after.setter
    def not_valid_after(self, not_valid_after: Optional[str]) -> None:
        self._not_valid_after = not_valid_after

    @property
    def certificate_algorithm(self) -> Optional[str]:
        return self._certificate_algorithm

    @certificate_algorithm.setter
    def certificate_algorithm(self, certificate_algorithm: Optional[str]) -> None:
        self._certificate_algorithm = certificate_algorithm

    @property
    def certificate_signature_algorithm(self) -> Optional[str]:
        return self._certificate_signature_algorithm

    @certificate_signature_algorithm.setter
    def certificate_signature_algorithm(self, certificate_signature_algorithm: Optional[str]) -> None:
        self._certificate_signature_algorithm = certificate_signature_algorithm

    @property
    def certificate_format(self) -> Optional[str]:
        return self._certificate_format

    @certificate_format.setter
    def certificate_format(self, certificate_format: Optional[str]) -> None:
        self._certificate_format = certificate_format

    @property
    def certificate_extensions(self) -> Optional[str]:
        return self._certificate_extensions

    @certificate_extensions.setter
    def certificate_extensions(self, certificate_extensions: Optional[str]) -> None:
        self._certificate_extensions = certificate_extensions

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CertificateProperties):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((
            self.subject_name, self.issuer_name, self.not_valid_before, self.not_valid_after,
            self.certificate_algorithm, self.certificate_signature_algorithm, self.certificate_format,
            self.certificate_extensions
        ))


@serializable.serializable_class
class RelatedCryptoMaterialProperties:
    """
    Our internal representation of the `relatedCryptoMaterialProperties` complex type.

    .. note::
        See the CBOM Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L688
    """

    def __init__(self, *, related_crypto_material_type: Optional[str] = None, size: Optional[int] = None,
                 format: Optional[str] = None, secured: Optional[bool] = None) -> None:
        self.related_crypto_material_type = related_crypto_material_type
        self.size = size
        self.format = format
        self.secured = secured

    @property
    def related_crypto_material_type(self) -> Optional[str]:
        return self._related_crypto_material_type

    @related_crypto_material_type.setter
    def related_crypto_material_type(self, related_crypto_material_type: Optional[str]) -> None:
        self._related_crypto_material_type = related_crypto_material_type

    @property
    def size(self) -> Optional[int]:
        return self._size

    @size.setter
    def size(self, size: Optional[int]) -> None:
        self._size = size

    @property
    def format(self) -> Optional[str]:
        return self._format

    @format.setter
    def format(self, format: Optional[str]) -> None:
        self._format = format

    @property
    def secured(self) -> Optional[bool]:
        return self._secured

    @secured.setter
    def secured(self, secured: Optional[bool]) -> None:
        self._secured = secured

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RelatedCryptoMaterialProperties):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((
            self.related_crypto_material_type, self.size, self.format, self.secured
        ))


@serializable.serializable_class
class ProtocolProperties:
    """
    Our internal representation of the `protocolProperties` complex type.

    .. note::
        See the CBOM Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L736
    """

    def __init__(self, *, tls_cipher_suites: Optional[Iterable[str]] = None,
                 ikev2_transform_types: Optional[IKEv2TransformTypes] = None) -> None:
        self.tls_cipher_suites = tls_cipher_suites or []
        self.ikev2_transform_types = ikev2_transform_types

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'cipherSuite')
    def tls_cipher_suites(self) -> "SortedSet[str]":
        return self._tls_cipher_suites

    @tls_cipher_suites.setter
    def tls_cipher_suites(self, tls_cipher_suites: Iterable[str]) -> None:
        self._tls_cipher_suites = SortedSet(tls_cipher_suites)

    @property  # type: ignore[misc]
    @serializable.view(SchemaVersion1Dot4CbomVersion1Dot0)
    def ikev2_transform_types(self) -> Optional[IKEv2TransformTypes]:
        return self._ikev2_transform_types

    @ikev2_transform_types.setter
    def ikev2_transform_types(self, ikev2_transform_types: Optional[IKEv2TransformTypes]) -> None:
        self._ikev2_transform_types = ikev2_transform_types

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ProtocolProperties):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((
            tuple(self.tls_cipher_suites), self.ikev2_transform_types
        ))


@serializable.serializable_class
class ConfidenceLevels:
    """
    Our internal representation of the `confidenceLevels` complex type.

    .. note::
        See the CBOM Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L790
    """

    def __init__(self, *, asset_type: Optional[int] = None, primitive: Optional[int] = None,
                 related_crypto_material_type: Optional[int] = None, variant: Optional[int] = None,
                 mode: Optional[int] = None, padding: Optional[int] = None, crypto_functions: Optional[int] = None,
                 subject_name: Optional[int] = None, issuer_name: Optional[int] = None,
                 not_valid_before: Optional[int] = None, not_valid_after: Optional[int] = None,
                 certificate_algorithm: Optional[int] = None, certificate_signature_algorithm: Optional[int] = None,
                 certificate_format: Optional[int] = None, certificate_extensions: Optional[int] = None,
                 tls_cipher_suites: Optional[int] = None, ikev2_transform_types: Optional[int] = None, ) -> None:
        self.asset_type = asset_type
        self.primitive = primitive
        self.related_crypto_material_type = related_crypto_material_type
        self.variant = variant
        self.mode = mode
        self.padding = padding
        self.crypto_functions = crypto_functions
        self.subject_name = subject_name
        self.issuer_name = issuer_name
        self.not_valid_before = not_valid_before
        self.not_valid_after = not_valid_after
        self.certificate_algorithm = certificate_algorithm
        self.certificate_signature_algorithm = certificate_signature_algorithm
        self.certificate_format = certificate_format
        self.certificate_extensions = certificate_extensions
        self.tls_cipher_suites = tls_cipher_suites
        self.ikev2_transform_types = ikev2_transform_types

    @property
    def asset_type(self) -> Optional[int]:
        return self._asset_type

    @asset_type.setter
    def asset_type(self, asset_type: Optional[int]) -> None:
        self._asset_type = asset_type

    @property
    def primitive(self) -> Optional[int]:
        return self._primitive

    @primitive.setter
    def primitive(self, primitive: Optional[int]) -> None:
        self._primitive = primitive

    @property
    def related_crypto_material_type(self) -> Optional[int]:
        return self._related_crypto_material_type

    @related_crypto_material_type.setter
    def related_crypto_material_type(self, related_crypto_material_type: Optional[int]) -> None:
        self._related_crypto_material_type = related_crypto_material_type

    @property
    def variant(self) -> Optional[int]:
        return self._variant

    @variant.setter
    def variant(self, variant: Optional[int]) -> None:
        self._variant = variant

    @property
    def mode(self) -> Optional[int]:
        return self._mode

    @mode.setter
    def mode(self, mode: Optional[int]) -> None:
        self._mode = mode

    @property
    def padding(self) -> Optional[int]:
        return self._padding

    @padding.setter
    def padding(self, padding: Optional[int]) -> None:
        self._padding = padding

    @property
    def crypto_functions(self) -> Optional[int]:
        return self._crypto_functions

    @crypto_functions.setter
    def crypto_functions(self, crypto_functions: Optional[int]) -> None:
        self._crypto_functions = crypto_functions

    @property
    def subject_name(self) -> Optional[int]:
        return self._subject_name

    @subject_name.setter
    def subject_name(self, subject_name: Optional[int]) -> None:
        self._subject_name = subject_name

    @property
    def issuer_name(self) -> Optional[int]:
        return self._issuer_name

    @issuer_name.setter
    def issuer_name(self, issuer_name: Optional[int]) -> None:
        self._issuer_name = issuer_name

    @property
    def not_valid_before(self) -> Optional[int]:
        return self._not_valid_before

    @not_valid_before.setter
    def not_valid_before(self, not_valid_before: Optional[int]) -> None:
        self._not_valid_before = not_valid_before

    @property
    def not_valid_after(self) -> Optional[int]:
        return self._not_valid_after

    @not_valid_after.setter
    def not_valid_after(self, not_valid_after: Optional[int]) -> None:
        self._not_valid_after = not_valid_after

    @property
    def certificate_algorithm(self) -> Optional[int]:
        return self._certificate_algorithm

    @certificate_algorithm.setter
    def certificate_algorithm(self, certificate_algorithm: Optional[int]) -> None:
        self._certificate_algorithm = certificate_algorithm

    @property
    def certificate_signature_algorithm(self) -> Optional[int]:
        return self._certificate_signature_algorithm

    @certificate_signature_algorithm.setter
    def certificate_signature_algorithm(self, certificate_signature_algorithm: Optional[int]) -> None:
        self._certificate_signature_algorithm = certificate_signature_algorithm

    @property
    def certificate_format(self) -> Optional[int]:
        return self._certificate_format

    @certificate_format.setter
    def certificate_format(self, certificate_format: Optional[int]) -> None:
        self._certificate_format = certificate_format

    @property
    def certificate_extensions(self) -> Optional[int]:
        return self._certificate_extensions

    @certificate_extensions.setter
    def certificate_extensions(self, certificate_extensions: Optional[int]) -> None:
        self._certificate_extensions = certificate_extensions

    @property
    def tls_cipher_suites(self) -> Optional[int]:
        return self._tls_cipher_suites

    @tls_cipher_suites.setter
    def tls_cipher_suites(self, tls_cipher_suites: Optional[int]) -> None:
        self._tls_cipher_suites = tls_cipher_suites

    @property
    def ikev2_transform_types(self) -> Optional[int]:
        return self._ikev2_transform_types

    @ikev2_transform_types.setter
    def ikev2_transform_types(self, ikev2_transform_types: Optional[int]) -> None:
        self._ikev2_transform_types = ikev2_transform_types

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ConfidenceLevels):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((
            self.asset_type, self.primitive, self.related_crypto_material_type, self.variant, self.mode, self.padding,
            self.crypto_functions, self.subject_name, self.issuer_name, self.not_valid_before, self.not_valid_after,
            self.certificate_algorithm, self.certificate_signature_algorithm, self.certificate_format,
            self.certificate_extensions, self.tls_cipher_suites, self.ikev2_transform_types
        ))


@serializable.serializable_class
class DetectionContext:
    """
    Our internal representation of the `detectionContext` complex type.

    .. note::
        See the CBOM Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L871
    """

    def __init__(self, *, file_path: Optional[str] = None, line_numbers: Optional[Iterable[int]] = None,
                 offsets: Optional[Iterable[int]] = None, symbols: Optional[Iterable[str]] = None,
                 keywords: Optional[Iterable[str]] = None, additional_context: Optional[str] = None) -> None:
        self.file_path = file_path
        self.line_numbers = line_numbers or []
        self.offsets = offsets or []
        self.symbols = symbols or []
        self.keywords = keywords or []
        self.additional_context = additional_context

    @property
    def file_path(self) -> Optional[str]:
        return self._file_path

    @file_path.setter
    def file_path(self, file_path: Optional[str]) -> None:
        self._file_path = file_path

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'lineNumber')
    def line_numbers(self) -> "SortedSet[int]":
        return self._line_numbers

    @line_numbers.setter
    def line_numbers(self, line_numbers: Iterable[int]) -> None:
        self._line_numbers = SortedSet(line_numbers)

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'offset')
    def offsets(self) -> "SortedSet[int]":
        return self._offsets

    @offsets.setter
    def offsets(self, offsets: Iterable[int]) -> None:
        self._offsets = SortedSet(offsets)

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'symbol')
    def symbols(self) -> "SortedSet[str]":
        return self._symbols

    @symbols.setter
    def symbols(self, symbols: Iterable[str]) -> None:
        self._symbols = SortedSet(symbols)

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'keyword')
    def keywords(self) -> "SortedSet[str]":
        return self._keywords

    @keywords.setter
    def keywords(self, keywords: Iterable[str]) -> None:
        self._keywords = SortedSet(keywords)

    @property
    def additional_context(self) -> Optional[str]:
        return self._additional_context

    @additional_context.setter
    def additional_context(self, additional_context: Optional[str]) -> None:
        self._additional_context = additional_context

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DetectionContext):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((
            self.file_path, tuple(self.line_numbers), tuple(self.offsets), tuple(self.symbols), tuple(self.keywords),
            self.additional_context
        ))

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, DetectionContext):
            return (ComparableTuple((self.file_path, self.line_numbers)) <
                    ComparableTuple((other.file_path, other.line_numbers)))
        return NotImplemented


@serializable.serializable_class
class CryptoProperties:
    """
    Our internal representation of the `cryptoProperties` complex type.

    .. note::
        See the CBOM Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L478
    """

    def __init__(self, *, asset_type: AssetType = None, algorithm_properties: Optional[AlgorithmProperties] = None,
                 certificate_properties: Optional[CertificateProperties] = None,
                 related_crypto_material_properties: Optional[RelatedCryptoMaterialProperties] = None,
                 protocol_properties: Optional[ProtocolProperties] = None,
                 classical_security_level: Optional[int] = None, nist_quantum_security_level: Optional[int] = None,
                 oid: Optional[str] = None, confidence_levels: Optional[ConfidenceLevels] = None,
                 scanner: Optional[str] = None, detection_context: Optional[Iterable[DetectionContext]] = None) -> None:
        self.asset_type = asset_type
        self.algorithm_properties = algorithm_properties
        self.certificate_properties = certificate_properties
        self.related_crypto_material_properties = related_crypto_material_properties
        self.protocol_properties = protocol_properties
        self.classical_security_level = classical_security_level
        self.nist_quantum_security_level = nist_quantum_security_level
        self.oid = oid
        self.confidence_levels = confidence_levels
        self.scanner = scanner
        self.detection_context = detection_context or []

    @property  # type: ignore[misc]
    @serializable.xml_attribute()
    def asset_type(self) -> AssetType:
        return self._asset_type

    @asset_type.setter
    def asset_type(self, asset_type: AssetType) -> None:
        self._asset_type = asset_type

    @property  # type: ignore[misc]
    @serializable.view(SchemaVersion1Dot4CbomVersion1Dot0)
    def algorithm_properties(self) -> Optional[AlgorithmProperties]:
        return self._algorithm_properties

    @algorithm_properties.setter
    def algorithm_properties(self, algorithm_properties: Optional[AlgorithmProperties]) -> None:
        self._algorithm_properties = algorithm_properties

    @property  # type: ignore[misc]
    @serializable.view(SchemaVersion1Dot4CbomVersion1Dot0)
    def certificate_properties(self) -> Optional[CertificateProperties]:
        return self._certificate_properties

    @certificate_properties.setter
    def certificate_properties(self, certificate_properties: Optional[CertificateProperties]) -> None:
        self._certificate_properties = certificate_properties

    @property  # type: ignore[misc]
    @serializable.view(SchemaVersion1Dot4CbomVersion1Dot0)
    def related_crypto_material_properties(self) -> Optional[RelatedCryptoMaterialProperties]:
        return self._related_crypto_material_properties

    @related_crypto_material_properties.setter
    def related_crypto_material_properties(self, related_crypto_material_properties: Optional[RelatedCryptoMaterialProperties]) -> None:
        self._related_crypto_material_properties = related_crypto_material_properties

    @property  # type: ignore[misc]
    @serializable.view(SchemaVersion1Dot4CbomVersion1Dot0)
    def protocol_properties(self) -> Optional[ProtocolProperties]:
        return self._protocol_properties

    @protocol_properties.setter
    def protocol_properties(self, protocol_properties: Optional[ProtocolProperties]) -> None:
        self._protocol_properties = protocol_properties

    @property
    def classical_security_level(self) -> Optional[int]:
        return self._classical_security_level

    @classical_security_level.setter
    def classical_security_level(self, classical_security_level: Optional[int]) -> None:
        self._classical_security_level = classical_security_level

    @property
    def nist_quantum_security_level(self) -> Optional[int]:
        return self._nist_quantum_security_level

    @nist_quantum_security_level.setter
    def nist_quantum_security_level(self, nist_quantum_security_level: Optional[int]) -> None:
        self._nist_quantum_security_level = nist_quantum_security_level

    @property
    def oid(self) -> Optional[str]:
        return self._oid

    @oid.setter
    def oid(self, oid: Optional[str]) -> None:
        self._oid = oid

    @property  # type: ignore[misc]
    @serializable.view(SchemaVersion1Dot4CbomVersion1Dot0)
    def confidence_levels(self) -> Optional[ConfidenceLevels]:
        return self._confidence_levels

    @confidence_levels.setter
    def confidence_levels(self, confidence_levels: Optional[ConfidenceLevels]) -> None:
        self._confidence_levels = confidence_levels

    @property
    def scanner(self) -> Optional[str]:
        return self._scanner

    @scanner.setter
    def scanner(self, scanner: Optional[str]) -> None:
        self._scanner = scanner

    @property  # type: ignore[misc]
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'detectionContext')
    def detection_context(self) -> "SortedSet[DetectionContext]":
        return self._detection_context

    @detection_context.setter
    def detection_context(self, detection_context: Iterable[DetectionContext]) -> None:
        self._detection_context = SortedSet(detection_context)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CryptoProperties):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((
            self.asset_type, self.algorithm_properties, self.certificate_properties,
            self.related_crypto_material_properties, self.protocol_properties, self.classical_security_level,
            self.nist_quantum_security_level, self.oid, self.confidence_levels, self.scanner,
            tuple(self.detection_context)
        ))
