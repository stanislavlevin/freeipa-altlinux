import abc
import typing

class CipherAlgorithm(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def name(self) -> str: ...
    @property
    @abc.abstractmethod
    def key_sizes(self) -> typing.FrozenSet[int]: ...
    @property
    @abc.abstractmethod
    def key_size(self) -> int: ...

class BlockCipherAlgorithm(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def block_size(self) -> int: ...
