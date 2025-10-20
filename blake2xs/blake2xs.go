/*Copyright (c) 2025 Haven F.C. Johnson under the MIT license
go bindings for the blake2xs algorithm
*/
package blake2xs

import (
	// #include "blake2.h"
	// #cgo CFLAGS: -O3
	"C"
	"hash"
	"unsafe"
)

type blake2xs_info struct{
	state C.blake2xs_state
	size int
}

func New(size int)hash.Hash{
	i:=new(blake2xs_info)
	i.size=size
	i.Reset()
	return i
}

func (*blake2xs_info)BlockSize()int{
	return 64
}

func (i *blake2xs_info)Reset(){
	if C.blake2xs_init(&i.state,C.size_t(i.size))<0{
		panic("blake2xs unable to init or reset")
	}
}

func (i *blake2xs_info)Size()int{
	return i.size
}

func (i *blake2xs_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2xs_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2xs_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2xs_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}

type blake2xs_keyed_info struct{
	state C.blake2xs_state
	size,key_len int
	key []byte
}

func New_Keyed(key []byte,digest_size int)hash.Hash{
	i:=new(blake2xs_keyed_info)
	if digest_size>0xFFFF{
		panic("blake2xs output length must be 65,535 bytes or lower")
	}
	i.key_len=len(key)
	if i.key_len>32{
		panic("blake2xs key length must be 32 bytes or lower")
	}
	i.key=key
	i.size=digest_size
	i.Reset()
	return i
}

func (*blake2xs_keyed_info)BlockSize()int{
	return 64
}

func (i *blake2xs_keyed_info)Reset(){
	if C.blake2xs_init_key(&i.state,C.size_t(i.size),unsafe.Pointer(&i.key[0]),C.size_t(i.key_len))<0{
		panic("blake2xs keyed unable to init or reset")
	}
}

func (i *blake2xs_keyed_info)Size()int{
	return i.size
}

func (i *blake2xs_keyed_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2xs_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2xs_keyed_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2xs_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}
