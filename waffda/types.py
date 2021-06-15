#!/usr/bin/env python
import idaapi


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

    def __init__(self, name_or_id=None, decl=None):
        '''
        Args:
            name_or_id: Name or IDA id of type
            decl: Valid C type declaration (with ;)
        '''
        if name_or_id is not None and decl is not None:
            raise ValueError('Use either name_or_id or decl, not both')

        if name_or_id is not None:
            if not isinstance(name_or_id, int):
                if not isinstance(name_or_id, str):
                    name_or_id = str(name_or_id)
                self._struct_id = idaapi.get_struc_id(name_or_id)
            else:
                self._struct_id = idaapi.get_struc_id(name_or_id)
        elif decl is not None:
            raise NotImplementedError()
        else:
            raise ValueError('Must pass either name_or_id or decl')

    def clone(self):
        '''
        Returns:
            Type: A new object identical to this one
        '''
        raise NotImplementedError()

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
        raise NotImplementedError()

    def is_volatile(self):
        '''
        Returns:
            bool: True if type is annotated as volatile, False otherwise
        '''
        raise NotImplementedError()

    def is_pointer(self):
        '''
        Returns:
            bool: True if represents a pointer type, False otherwise

        `T` -> False
        `T *` -> True
        '''
        raise NotImplementedError()

    def is_array(self):
        '''
        Returns:
            bool: True if represents an array type, False otherwise

        Example:
            `T` -> False
            `T[]` -> True
        '''
        raise NotImplementedError()

    def is_function(self):
        '''
        Returns:
            bool: True if represents a function type, False otherwise
        '''
        raise NotImplementedError()

    def get_size(self):
        raise NotImplementedError()

    def get_contained_type(self):
        '''
        Get type pointer to, i.e. `T *` -> `T`

        Returns:
            Type: The type pointer to by this instance
        '''
        raise NotImplementedError()

    def get_pointer_to(self):
        '''
        Conver to pointer type, i.e. `T` -> `T *`

        Returns:
            Type: A type pointing to the type represented by this instance
        '''
        raise NotImplementedError()

    def set_element_type(self, element_type):
        '''
        Args:
            element_type (Type): New element type
        '''
        raise NotImplementedError()

    def get_element_count(self):
        '''
        Returns:
            int: Element count of array type
        '''
        raise NotImplementedError()

    def set_element_count(self, element_count):
        '''
        Args:
            element_count (int): New element count
        '''
        raise NotImplementedError()

    def get_args(self):
        '''
        Returns:
            [Type]: Argument type of function type
        '''
        raise NotImplementedError()

    def get_ret_type(self):
        '''
        Returns:
            Type: Return type of function type
        '''
        raise NotImplementedError()

    def set_args(self, args):
        '''
        Args:
            args ([Type]): New argument types
        '''
        raise NotImplementedError()

    def set_ret_type(self, ret_type):
        '''
        Args:
            ret_type (Type): New return type
        '''
        raise NotImplementedError()

    def get_name(self):
        '''
        Returns:
            str: Name of a struct type
        '''
        raise NotImplementedError()

    def get_fields(self):
        '''
        Returns:
            [Field]: Fields of a struct type
        '''
        raise NotImplementedError()

    def set_name(self, struct_name):
        '''
        Args:
            struct_name (str): New struct name
        '''
        raise NotImplementedError()

    def set_fields(self, fields):
        '''
        Args:
            struct_name ([Field]): New struct fields
        '''
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()


class Field:
    '''
    TODO:
    - change name
    - change type
    - get offset within struct
    - get xrefs to field
    '''
    def __init__(self, name, size, type):
        pass
