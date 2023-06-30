/*Copyright (c) 2023 Tracy-Tzu under the MIT license
go bindings for the blake2xb algorithm
*/
package blake2xb

import (
	// #include "blake2.h"
	// #cgo CFLAGS: -O3
	"C"
	"hash"
	"unsafe"
)

type blake2xb_info struct{
	state C.blake2xb_state
	size int
}

func New(size int)hash.Hash{
	i:=new(blake2xb_info)
	i.size=size
	i.Reset()
	return i
}

func (*blake2xb_info)BlockSize()int{
	return 128
}

func (i *blake2xb_info)Reset(){
	if C.blake2xb_init(&i.state,C.size_t(i.size))<0{
		panic("blake2xb unable to init or reset")
	}
}

func (i *blake2xb_info)Size()int{
	return i.size
}

func (i *blake2xb_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2xb_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2xb_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2xb_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}

type blake2xb_keyed_info struct{
	state C.blake2xb_state
	size,key_len int
	key []byte
}

func New_Keyed(key []byte,digest_size int)hash.Hash{
	i:=new(blake2xb_keyed_info)
	if digest_size>0xFFFFFFFF{
		panic("blake2xb output length must be 4,294,967,295 bytes or lower")
	}
	i.key_len=len(key)
	if i.key_len>64{
		panic("blake2xb key length must be 64 bytes or lower")
	}
	i.key=key
	i.size=digest_size
	i.Reset()
	return i
}

func (*blake2xb_keyed_info)BlockSize()int{
	return 128
}

func (i *blake2xb_keyed_info)Reset(){
	if C.blake2xb_init_key(&i.state,C.size_t(i.size),unsafe.Pointer(&i.key[0]),C.size_t(i.key_len))<0{
		panic("blake2xb keyed unable to init or reset")
	}
}

func (i *blake2xb_keyed_info)Size()int{
	return i.size
}

func (i *blake2xb_keyed_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2xb_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2xb_keyed_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2xb_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}
