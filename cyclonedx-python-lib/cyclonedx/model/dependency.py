# encoding: utf-8

# This file is part of CycloneDX Python Lib
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Iterable, List, Optional, Set

import serializable
from sortedcontainers import SortedSet

from cyclonedx.model import ComparableTuple
from cyclonedx.serialization import BomRefHelper

from .bom_ref import BomRef
from ..schema.schema import SchemaVersion1Dot4CbomVersion1Dot0


class DependencyDependencies(serializable.BaseHelper):  # type: ignore

    @classmethod
    def serialize(cls, o: object) -> List[str]:
        if isinstance(o, SortedSet):
            return list(map(lambda i: str(i.ref), o))

        raise ValueError(f'Attempt to serialize a non-Dependency: {o.__class__}')

    @classmethod
    def deserialize(cls, o: object) -> Set["Dependency"]:
        dependencies: Set["Dependency"] = set()
        if isinstance(o, list):
            for v in o:
                dependencies.add(Dependency(ref=BomRef(value=v)))
        return dependencies


class DependencyType(str, Enum):
    """
    Enum object that defines the permissible 'types' for a dependency relationship according to the CBOM schema.

    .. note::
        See the CycloneDX Schema definition: https://github.com/IBM/CBOM/blob/main/bom-1.4-cbom-1.0.schema.json#L1105
    """
    IMPLEMENTS = 'implements'
    USES = 'uses'


@serializable.serializable_class
class Dependency:
    """
    Models a Dependency within a BOM.

    .. note::
        See https://cyclonedx.org/docs/1.4/xml/#type_dependencyType
    """

    def __init__(self, ref: BomRef, dependencies: Optional[Iterable["Dependency"]] = None,
                 dependency_type: Optional[DependencyType] = None) -> None:
        self.ref = ref
        self.dependencies = SortedSet(dependencies or [])
        self.dependency_type = dependency_type

    @property  # type: ignore[misc]
    @serializable.type_mapping(BomRefHelper)
    @serializable.xml_attribute()
    def ref(self) -> BomRef:
        return self._ref

    @ref.setter
    def ref(self, ref: BomRef) -> None:
        self._ref = ref

    @property  # type: ignore[misc]
    @serializable.json_name('dependsOn')
    @serializable.type_mapping(DependencyDependencies)
    @serializable.xml_array(serializable.XmlArraySerializationType.FLAT, 'dependency')
    def dependencies(self) -> "SortedSet[Dependency]":
        return self._dependencies

    @dependencies.setter
    def dependencies(self, dependencies: Iterable["Dependency"]) -> None:
        self._dependencies = SortedSet(dependencies)

    @property  # type: ignore[misc]
    @serializable.view(SchemaVersion1Dot4CbomVersion1Dot0)
    @serializable.xml_attribute()
    def dependency_type(self) -> DependencyType:
        return self._dependency_type

    @dependency_type.setter
    def dependency_type(self, dependency_type: DependencyType) -> None:
        self._dependency_type = dependency_type

    def dependencies_as_bom_refs(self) -> Set[BomRef]:
        return set(map(lambda d: d.ref, self.dependencies))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Dependency):
            return hash(other) == hash(self)
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, Dependency):
            return ComparableTuple((self.ref, tuple(self.dependencies))) < ComparableTuple(
                (other.ref, tuple(other.dependencies)))
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.ref, tuple(self.dependencies), self.dependency_type))

    def __repr__(self) -> str:
        return f'<Dependency ref={self.ref}, targets={len(self.dependencies)}>'


class Dependable(ABC):
    """
    Dependable objects can be part of the Dependency Graph
    """

    @property
    @abstractmethod
    def bom_ref(self) -> BomRef:
        pass
