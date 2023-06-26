import copy
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Iterator

import pydantic
from pydantic import Field, validator  # type: ignore


def serialize_datetime(dt: datetime):
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc).isoformat()

    return dt.isoformat()


def get_all_bases(cls: type, bases: Optional[list[type]] = None):
    bases = bases or []
    bases.append(cls)
    for c in cls.__bases__:
        get_all_bases(c, bases)
    return tuple(bases)


def merge_dict(base: dict[Any, Any], overlay: dict[Any, Any]):
    for k, v in base.items():
        if isinstance(v, dict):
            merge_dict(v, overlay.setdefault(k, {}))  # type: ignore
        else:
            if k not in overlay:
                overlay[k] = v

    return overlay


class GradleSpecifier:
    """
    A gradle specifier - a maven coordinate. Like one of these:
    "org.lwjgl.lwjgl:lwjgl:2.9.0"
    "net.java.jinput:jinput:2.0.5"
    "net.minecraft:launchwrapper:1.5"
    """

    def __init__(
        self,
        group: str,
        artifact: str,
        version: str,
        classifier: Optional[str] = None,
        extension: Optional[str] = None,
    ):
        if extension is None:
            extension = "jar"
        self.group = group
        self.artifact = artifact
        self.version = version
        self.classifier = classifier
        self.extension = extension

    def __str__(self):
        ext = ""
        if self.extension != "jar":
            ext = "@%s" % self.extension
        if self.classifier:
            return "%s:%s:%s:%s%s" % (
                self.group,
                self.artifact,
                self.version,
                self.classifier,
                ext,
            )
        else:
            return "%s:%s:%s%s" % (self.group, self.artifact, self.version, ext)

    def filename(self):
        if self.classifier:
            return "%s-%s-%s.%s" % (
                self.artifact,
                self.version,
                self.classifier,
                self.extension,
            )
        else:
            return "%s-%s.%s" % (self.artifact, self.version, self.extension)

    def base(self):
        return "%s/%s/%s/" % (self.group.replace(".", "/"), self.artifact, self.version)

    def path(self):
        return self.base() + self.filename()

    def __repr__(self):
        return f"GradleSpecifier('{self}')"

    def is_lwjgl(self):
        return self.group in (
            "org.lwjgl",
            "org.lwjgl.lwjgl",
            "net.java.jinput",
            "net.java.jutils",
        )

    def is_log4j(self):
        return self.group == "org.apache.logging.log4j"

    def __eq__(self, other: Any):
        if isinstance(other, GradleSpecifier):
            return str(self) == str(other)
        else:
            return False

    def __lt__(self, other: 'GradleSpecifier'):
        return str(self) < str(other)

    def __gt__(self, other: 'GradleSpecifier'):
        return str(self) > str(other)

    def __hash__(self):
        return hash(str(self))

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def from_string(cls, v: str):
        ext_split = v.split("@")

        components = ext_split[0].split(":")
        group = components[0]
        artifact = components[1]
        version = components[2]

        extension = None
        if len(ext_split) == 2:
            extension = ext_split[1]

        classifier = None
        if len(components) == 4:
            classifier = components[3]
        return cls(group, artifact, version, classifier, extension)

    @classmethod
    def validate(cls, v: 'str | GradleSpecifier'):
        if isinstance(v, cls):
            return v
        if isinstance(v, str):
            return cls.from_string(v)
        raise TypeError("Invalid type")


class MetaBase(pydantic.BaseModel):
    def dict(self, **kwargs: Any) -> Dict[str, Any]:
        for k in ["by_alias"]:
            if k in kwargs:
                del kwargs[k]

        return super(MetaBase, self).dict(by_alias=True, **kwargs)

    def json(self, **kwargs: Any) -> str:
        for k in ["exclude_none", "sort_keys", "indent"]:
            if k in kwargs:
                del kwargs[k]

        return super(MetaBase, self).json(
            exclude_none=True, sort_keys=False, by_alias=True, indent=2, **kwargs
        )

    def write(self, file_path: str):
        with open(file_path, "w") as f:
            f.write(self.json())

    def merge(self, other: 'MetaBase'):
        """
        Merge other object with self.
        - Concatenates lists
        - Combines sets
        - Merges dictionaries (other takes priority)
        - Recurses for all fields that are also MetaBase classes
        - Overwrites for any other field type (int, string, ...)
        """
        assert type(other) is type(self)
        for key, field in self.__fields__.items():
            ours = getattr(self, key)
            theirs = getattr(other, key)
            if theirs is None:
                continue
            if ours is None:
                setattr(self, key, theirs)
                continue

            if isinstance(ours, list):
                ours += theirs
            elif isinstance(ours, set):
                ours |= theirs
            elif isinstance(ours, dict):
                result = merge_dict(ours, copy.deepcopy(theirs)) # type: ignore
                setattr(self, key, result)
            elif MetaBase in get_all_bases(field.type_):
                ours.merge(theirs)
            else:
                setattr(self, key, theirs)

    def __hash__(self): #type: ignore
        return hash(self.json())

    class Config:
        allow_population_by_field_name = True

        json_encoders = {datetime: serialize_datetime, GradleSpecifier: str}


class OSRule(MetaBase):
    @validator("name")
    def name_must_be_os(cls, v: str):
        assert v in [
            "osx",
            "linux",
            "windows",
            "windows-arm64",
            "osx-arm64",
            "linux-arm64",
            "linux-arm32",
        ]
        return v

    name: str
    version: Optional[str]


class MojangRule(MetaBase):
    @validator("action")
    def action_must_be_allow_disallow(cls, v: str):
        assert v in ["allow", "disallow"]
        return v

    action: str
    os: Optional[OSRule]


class MojangRules(MetaBase):
    __root__: List[MojangRule]

    def __iter__(self) -> Iterator[MojangRule]:  #type: ignore
        return iter(self.__root__)

    def __getitem__(self, item: int) -> MojangRule:
        return self.__root__[item]


class MojangArtifactBase(MetaBase):
    sha1: Optional[str]
    size: Optional[int]
    url: str


class MojangArtifact(MojangArtifactBase):
    path: Optional[str]


class MojangLibraryDownloads(MetaBase):
    artifact: Optional[MojangArtifact]
    classifiers: Optional[Dict[Any, MojangArtifact]]


class MojangLibraryExtractRules(MetaBase):
    """
    "rules": [
        {
            "action": "allow"
        },
        {
            "action": "disallow",
            "os": {
                "name": "osx"
            }
        }
    ]
    """

    exclude: List[str]  # TODO maybe drop this completely?


class MojangLibrary(MetaBase):
    extract: Optional[MojangLibraryExtractRules]
    name: Optional[GradleSpecifier]
    downloads: Optional[MojangLibraryDownloads]
    natives: Optional[Dict[str, str]]
    rules: Optional[MojangRules]


class Library(MojangLibrary):
    url: Optional[str]
    mmcHint: Optional[str] = Field(None, alias="MMC-hint")


class LibraryPatch(MetaBase):
    comment: Optional[str] = Field(None, alias="_comment")
    match: List[GradleSpecifier]
    override: Optional[Library]
    additionalLibraries: Optional[List[Library]]
    patchAdditionalLibraries: Optional[bool]

    def applies(self, target: Library) -> bool:
        return target.name in self.match


class LibraryPatches(MetaBase):
    __root__: List[LibraryPatch]

    def __iter__(self) -> Iterator[LibraryPatch]:
        return iter(self.__root__)

    def __getitem__(self, item) -> LibraryPatch:
        return self.__root__[item]


def restore_split_natives(specifier: GradleSpecifier) -> bool:
    import re
    combined_natives = re.compile(r"(.+)-(natives-\w+-[a-zA-Z0-9]+)")
    match = combined_natives.match(specifier.artifact)
    if match is not None:
        old = copy.deepcopy(specifier)
        specifier.artifact = match.group(1)
        specifier.classifier = match.group(2)
        print(f"Restoring split natives: {old} -> {specifier}")
        return True
    return False



def main():
    library_patches: LibraryPatches = LibraryPatches.parse_file(
        "library-patches.json"
    )
    old_patches = copy.deepcopy(library_patches)
    change = False
    for patch in library_patches:
        for name in patch.match:
            if restore_split_natives(name):
                change = True

        if patch.override is not None:
            if patch.override.name is not None:
                if restore_split_natives(patch.override.name):
                    change = True

        if patch.additionalLibraries is not None:
            for lib in patch.additionalLibraries:
                if lib.name is not None:
                    if restore_split_natives(lib.name):
                        change = True
    if change:
        print("Split native restored: backing up old patches.")
        old_patches.write("library-patches.json.bk")
    library_patches.write("library-patches.json")




if __name__ == "__main__":
    main()
