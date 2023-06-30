/*Copyright (c) 2023 Tracy-Tzu under the MIT license
go bindings for the blake2bp algorithm
*/
package blake2bp

import (
	// #include "blake2.h"
	// #cgo CFLAGS: -O3
	"C"
	"hash"
	"unsafe"
)

type blake2bp_info struct{
	state C.blake2bp_state
	size int
}

func Sum348(data []byte)[20]byte{
	var sum [20]byte
	if data==nil{
		panic("nil data passed to Sum348")
	}
	C.blake2bp(unsafe.Pointer(&sum[0]),20,unsafe.Pointer(&data[0]),C.size_t(len(data)),nil,0)
	return sum
}

func Sum512(data []byte)[64]byte{
	var sum [64]byte
	if data==nil{
		panic("nil data passed to Sum512")
	}
	C.blake2bp(unsafe.Pointer(&sum[0]),64,unsafe.Pointer(&data[0]),C.size_t(len(data)),nil,0)
	return sum
}

func New(size int)hash.Hash{
	i:=new(blake2bp_info)
	i.size=size
	i.Reset()
	return i
}

func (*blake2bp_info)BlockSize()int{
	return 128
}

func (i *blake2bp_info)Reset(){
	if C.blake2bp_init(&i.state,C.size_t(i.size))<0{
		panic("blake2bp unable to init or reset")
	}
}

func (i *blake2bp_info)Size()int{
	return i.size
}

func (i *blake2bp_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2bp_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2bp_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2bp_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}

type blake2bp_keyed_info struct{
	state C.blake2bp_state
	size,key_len int
	key []byte
}

func New_Keyed(key []byte,digest_size int)hash.Hash{
	i:=new(blake2bp_keyed_info)
	if digest_size>64{
		panic("blake2bp output length must be 64 bytes or lower")
	}
	i.key_len=len(key)
	if i.key_len>64{
		panic("blake2bp key length must be 64 bytes or lower")
	}
	i.key=key
	i.size=digest_size
	i.Reset()
	return i
}

func (*blake2bp_keyed_info)BlockSize()int{
	return 128
}

func (i *blake2bp_keyed_info)Reset(){
	if C.blake2bp_init_key(&i.state,C.size_t(i.size),unsafe.Pointer(&i.key[0]),C.size_t(i.key_len))<0{
		panic("blake2bp keyed unable to init or reset")
	}
}

func (i *blake2bp_keyed_info)Size()int{
	return i.size
}

func (i *blake2bp_keyed_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2bp_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2bp_keyed_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2bp_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}
