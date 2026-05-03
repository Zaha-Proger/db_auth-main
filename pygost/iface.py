from abc import ABCMeta
from abc import abstractmethod


class PEP247(metaclass=ABCMeta):
    @property
    @abstractmethod
    def digest_size(self) -> int:
        """The size of the digest produced by the hashing objects.
        """

    @abstractmethod
    def copy(self) -> object:
        """Return a separate copy of this hashing object.
        """

    @abstractmethod
    def update(self, data: bytes) -> bytes:
        """Hash data into the current state of the hashing object.
        """

    @abstractmethod
    def digest(self) -> bytes:
        """Return the hash value as a string containing 8-bit data.
        """

    def hexdigest(self) -> str:
        """Return the hash value as a string containing hexadecimal digits.
        """
        return self.digest().hex()
