/*Copyright (c) 2023 Tracy-Tzu under the MIT license
go bindings for the blake2sp algorithm
*/
package blake2sp

import (
	// #include "blake2.h"
	// #cgo CFLAGS: -O3
	"C"
	"hash"
	"unsafe"
)

type blake2sp_info struct{
	state C.blake2sp_state
	size int
}

func Sum256(data []byte)[32]byte{
	var sum [32]byte
	if data==nil{
		panic("nil data passed to Sum256")
	}
	C.blake2sp(unsafe.Pointer(&sum[0]),32,unsafe.Pointer(&data[0]),C.size_t(len(data)),nil,0)
	return sum
}

func New(size int)hash.Hash{
	i:=new(blake2sp_info)
	i.size=size
	i.Reset()
	return i
}

func (*blake2sp_info)BlockSize()int{
	return 64
}

func (i *blake2sp_info)Reset(){
	if C.blake2sp_init(&i.state,C.size_t(i.size))<0{
		panic("blake2sp unable to init or reset")
	}
}

func (i *blake2sp_info)Size()int{
	return i.size
}

func (i *blake2sp_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2sp_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2sp_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2sp_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}

type blake2sp_keyed_info struct{
	state C.blake2sp_state
	size,key_len int
	key []byte
}

func New_Keyed(key []byte,digest_size int)hash.Hash{
	i:=new(blake2sp_keyed_info)
	if digest_size>32{
		panic("blake2sp output length must be 32 bytes or lower")
	}
	i.key_len=len(key)
	if i.key_len>32{
		panic("blake2sp key length must be 32 bytes or lower")
	}
	i.key=key
	i.size=digest_size
	i.Reset()
	return i
}

func (*blake2sp_keyed_info)BlockSize()int{
	return 64
}

func (i *blake2sp_keyed_info)Reset(){
	if C.blake2sp_init_key(&i.state,C.size_t(i.size),unsafe.Pointer(&i.key[0]),C.size_t(i.key_len))<0{
		panic("blake2sp keyed unable to init or reset")
	}
}

func (i *blake2sp_keyed_info)Size()int{
	return i.size
}

func (i *blake2sp_keyed_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2sp_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2sp_keyed_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2sp_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}
