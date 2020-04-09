#!python


from .cbor import loads, dumps, load, dump, loads_in_place

from .cbor import Tag
from .tagmap import TagMapper, ClassTag, UnknownTagException
from .VERSION import __doc__ as __version__

__all__ = [
    'loads', 'dumps', 'load', 'dump','loads_in_place'
    'Tag',
    'TagMapper', 'ClassTag', 'UnknownTagException',
    '__version__',
]
