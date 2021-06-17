#!/usr/bin/env python
import idaapi
import enum


def get_pointer_size():
    tif = idaapi.tinfo_t()
    idaapi.parse_decl(tif, idaapi.cvar.idati, 'void *;', idaapi.PT_TYP)
    return tif.get_size()


POITNER_SIZE = get_pointer_size()

TYPE_ALIASES = {
    'int': 'int32_t',
    'uint': 'uint32_t',
    'boolean': 'bool',
}


class CallingConventions(enum.Enum):
    invalid = 0
    unknown = 16
    voidarg = 32
    cdecl = 48
    ellipsis = 64
    stdcall = 80
    pascal = 96
    fastcall = 112
    thiscall = 128
    manual = 144
    spoiled = 160

    # reserve4 = 176
    # reserve3 = 192
    # speciale = 208
    # specialp = 224
    # mask = 240


class Type:
    '''
    Wrapper class to represent types in IDA

    Example:
        int32_t = Type('int')
        int16_t = Type(<ordinal of int16_t>)
        anonymous_struct_t = Type(decl='struct { int a; int b; };')
        bool_array_t = ArrayType('bool', 10) # bool[10]

        int32_array_t = int32_t.array_of()
        5_inr16_array_t = int16_t.array_of(5)
        anonymous_struct_ptr_t = anonymous_struct_t.get_pointer_to()

        void_t = Type('void *').points_to()

        print(void_t.is_pointer()) # False
        print(int32_array_t.is_array()) # True
        print(anonymous_struct_t.is_struct()) # True
        print(anonymous_struct_ptr_t.points_to().is_anonymous()) # True
    '''

    def __init__(self, decl=None):
        '''
        Args:
            decl: Name of type or valid C type declaration (with ;)
        '''
        self._decl = '?'

        self._is_const = False
        self._is_volatile = False

        self._contained_type = None
        self._is_ptr = False
        self._is_array = False
        self._element_count = 0

        self._is_function = False
        self._ret_type = None
        self._arg_types = list()
        self._cc = CallingConventions.invalid

        self._is_struct = False
        self._struct_name = ''
        self._fields = list()

        if decl is not None:
            if isinstance(decl, idaapi.tinfo_t):
                decl = decl.dstr()

            if decl in TYPE_ALIASES:
                decl = TYPE_ALIASES[decl]

            if not isinstance(decl, str):
                decl = str(decl)

            if len(decl) == 0:
                raise ValueError('Empty decl')

            decl = decl if decl.endswith(';') else f'{decl};'
            tif = idaapi.tinfo_t()
            success = idaapi.parse_decl(tif, idaapi.cvar.idati, decl, idaapi.PT_TYP)
            if success is None:
                raise ValueError(f'Bad declaration "{decl}"')

            self._decl = tif.dstr()

            self._is_const = tif.is_const()
            self._is_volatile = tif.is_volatile()

            self._is_ptr = tif.is_ptr()
            self._is_array = tif.is_array()
            self._is_function = tif.is_funcptr()

            if self._is_ptr and not self._is_function:
                self._contained_type = Type(tif.get_pointed_object().dstr())
            elif self._is_array:
                self._element_count = tif.get_array_nelems()
                self._contained_type = Type(tif.get_array_element().dstr())

            if self._is_function:
                self._is_ptr = False  # For compatability's sake
                self._ret_type = Type(tif.get_rettype().dstr())
                func_type_data = idaapi.func_type_data_t()
                func_tif = tif.get_pointed_object()
                func_tif.get_func_details(func_type_data)
                try:
                    self._cc = CallingConventions(func_type_data.cc)
                except ValueError:
                    self._cc = CallingConventions(func_type_data.cc ^ 3)
                for idx in range(tif.get_nargs()):
                    self._arg_types.append(Type(tif.get_nth_arg(idx).dstr()))

            if tif.is_struct():
                self._is_struct = True
                self._struct_name = tif.get_type_name()
                # TODO: extract fields
                raise NotImplementedError()

    def clone(self):
        '''
        Returns: Type: A new object identical to this one
        '''
        return Type(self.get_tinfo().dstr())

    def get_tinfo(self):
        '''
        Returns:
            idaapi.tinto_f: tinfo_t object representing this Type object
        '''
        if self.is_pointer():
            ptr_type_data = idaapi.ptr_type_data_t()
            ptr_type_data.obj_type = self._contained_type.get_tinfo()
            tif = idaapi.tinfo_t()
            tif.create_ptr(ptr_type_data)
        elif self.is_array():
            array_type_data = idaapi.array_type_data_t()
            array_type_data.elem_type = self._contained_type.get_tinfo()
            array_type_data.base = 0
            array_type_data.nelems = self._element_count
            tif = idaapi.tinfo_t()
            tif.create_array(array_type_data)
        elif self.is_function():
            func_type_data = idaapi.func_type_data_t()
            func_type_data.rettype = self._ret_type.get_tinfo()
            func_type_data.cc = self._cc.value
            for arg in self._arg_types:
                funcarg = idaapi.funcarg_t()
                funcarg.type = arg.get_tinfo()
                func_type_data.push_back(funcarg)
            func_tif = idaapi.tinfo_t()
            func_tif.create_func(func_type_data)
            tif = idaapi.tinfo_t()
            ptr_type_data = idaapi.ptr_type_data_t()
            ptr_type_data.obj_type = func_tif
            tif.create_ptr(ptr_type_data)
        elif self.is_struct():
            raise NotImplementedError()
        else:
            tif = idaapi.tinfo_t()
            idaapi.parse_decl(tif, idaapi.cvar.idati, f'{self._decl};', idaapi.PT_TYP)
            return tif

        # TODO: add const/volatile information
        return tif

    def register(self):
        '''
        Register a struct type, also used to propagate changes made to the struct type

        Example:
            # must have a name to register
            StructType('person_t', {'age':'int', 'name':'const char *'}).register()
            person_t = Type('person_t')
        '''
        raise NotImplementedError()

    def is_const(self):
        '''
        Returns:
            bool: True if value is annotated as const, False otherwise
        '''
        return self._is_const

    def is_volatile(self):
        '''
        Returns:
            bool: True if type is annotated as volatile, False otherwise
        '''
        return self._is_volatile

    def set_const(self):
        self._is_const = True

    def set_volatile(self):
        self._is_volatile = True

    def clear_const(self):
        self._is_const = False

    def clear_volatile(self):
        self._is_volatile = False

    def toggle_const(self):
        self.is_const = not self._is_const

    def toggle_volatile(self):
        self._is_volatile = not self._is_volatile

    def is_pointer(self):
        '''
        Returns:
            bool: True if represents a pointer type, False otherwise

        `T` -> False
        `T *` -> True
        '''
        return self._is_ptr

    def is_array(self):
        '''
        Returns:
            bool: True if represents an array type, False otherwise

        Example:
            `T` -> False
            `T[]` -> True
        '''
        return self._is_array

    def is_function(self):
        '''
        Returns:
            bool: True if represents a function type, False otherwise
        '''
        return self._is_function

    def get_size(self):
        '''
        Returns:
            int: Size in bytes
        '''
        if self.is_array():
            return self._element_count * self._contained_type.get_size()
        elif self.is_pointer or self.is_function():
            return POINTER_SIZE
        return self.get_tinfo().get_size()

    def get_pointer_to(self):
        '''
        Convert to pointer type, i.e. `T` -> `T *`

        Returns:
            Type: A type pointing to the type represented by this instance
        '''
        if self.get_tinfo().dstr() == '':
            raise ValueError('Cannot create pointer to empty type')

        pointer_type = Type()
        pointer_type._is_ptr = True
        pointer_type._contained_type = self.clone()

        return pointer_type

    def get_array_of(self, element_count):
        '''
        Create an array type whose contained type is the current type

        Args:
            element_count (int): Count of elements for the array type

        Returns:
            Type: A type representing the specified array
        '''
        if not isinstance(element_count, int) or element_count <= 0:
            raise ValueError('Must have a natural number for element count')

        array_type = Type()
        array_type._is_array = True
        array_type._element_count = element_count
        array_type._contained_type = self.clone()

        return array_type

    def get_contained_type(self):
        '''
        Get type pointer to, i.e. `T *` -> `T`, `T[]` -> `T`

        Returns:
            Type: The type pointer to by this instance
        '''
        if not self.is_array() and not self.is_pointer():
            raise ValueError('Not a boxed type')
        return self._contained_type.clone()

    def set_contained_type(self, contained_type):
        '''
        Args:
            contained_type (Type): New contained type
        '''
        if not self.is_array() and not self.is_pointer():
            raise ValueError('Not a boxed type')
        self._contained_type = contained_type

    def get_element_count(self):
        '''
        Returns:
            int: Element count of array type
        '''
        if not self.is_array():
            raise ValueError('Not an array type')
        return self._element_count

    def set_element_count(self, element_count):
        '''
        Args:
            element_count (int): New element count
        '''
        if not self.is_array():
            raise ValueError('Not an array type')
        self._element_count = element_count

    def get_args(self):
        '''
        Returns:
            [Type]: Argument type of function type
        '''
        if not self.is_function():
            raise ValueError('Not a function type')
        return self._arg_types

    def get_ret_type(self):
        '''
        Returns:
            Type: Return type of function type
        '''
        if not self.is_function():
            raise ValueError('Not a function type')
        return self._ret_type

    def get_calling_convention(self):
        '''
        Returns:
            CallingConventions: CC of function type
        '''
        if not self.is_function():
            raise ValueError('Not a function type')
        return self._cc

    def set_args(self, args):
        '''
        Args:
            args ([Type]): New argument types
        '''
        if not self.is_function():
            raise ValueError('Not a function type')
        self._arg_types = args

    def set_ret_type(self, ret_type):
        '''
        Args:
            ret_type (Type): New return type
        '''
        if not self.is_function():
            raise ValueError('Not a function type')
        self._ret_type = ret_type

    def set_calling_convention(self, cc):
        '''
        Args:
            cc (CallingConventions|int): New calling convention
        '''
        if not self.is_function():
            raise ValueError('Not a function type')
        if not isinstance(cc, CallingConventions):
            cc = CallingConventions(cc)
        self._cc = cc

    def is_struct(self):
        '''
        Returns:
            bool: True if is a struct type, False otherwise
        '''
        return self._is_struct

    def get_struct_name(self):
        '''
        Returns:
            str: Name of a struct type
        '''
        return self._struct_name

    def get_fields(self):
        '''
        Returns:
            [Field]: Fields of a struct type
        '''
        if not self.is_struct():
            raise ValueError('Not a struct type')
        return self._fields

    def set_struct_name(self, struct_name):
        '''
        Args:
            struct_name (str): New struct name
        '''
        self._struct_name = struct_name

    def set_fields(self, fields):
        '''
        Args:
            struct_name ([Field]): New struct fields
        '''
        if not self.is_struct():
            raise ValueError('Not a struct type')
        self._fields = fields

    def __str__(self):
        return self.get_tinfo().dstr()

    def __eq__(self, other):
        return self.get_tinfo() == other.get_tinfo()


class Field:
    '''
    TODO:
    - change name
    - change type
    - get offset within struct
    - get xrefs to field
    '''
    def __init__(self, name, size, type):
        raise NotImplementedError()
