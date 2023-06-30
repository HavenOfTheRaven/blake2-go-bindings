/*Copyright (c) 2023 Tracy-Tzu under the MIT license
go bindings for the blake2s algorithm
*/
package blake2s

import (
	// #include "blake2.h"
	// #cgo CFLAGS: -O3
	"C"
	"hash"
	"unsafe"
)

type Param struct{
	Salt,Personal [8]byte
	Tree *Tree
	Size byte
}

type Tree struct{
	Offset,Max_leaf_size uint32
	xof_size uint16
	Fanout,Max_depth,Depth,Inner_size byte
	Last_node bool
}

type blake2s_info struct{
	param C.blake2s_param
	state C.blake2s_state
	last_node bool
}

func Sum256(data []byte)[32]byte{
	var sum [32]byte
	if data==nil{
		panic("nil data passed to Sum256")
	}
	C.blake2s(unsafe.Pointer(&sum[0]),32,unsafe.Pointer(&data[0]),C.size_t(len(data)),nil,0)
	return sum
}

func New(param *Param)hash.Hash{
	i:=new(blake2s_info)
	if param==nil{
		i.param.digest_length=32
		i.param.fanout=1
		i.param.depth=1
		i.Reset()
		return i
	}
	if param.Size==0{
		i.param.digest_length=32
	}else{
		i.param.digest_length=C.uint8_t(param.Size)
	}
	salt:=(*[8]byte)(unsafe.Pointer(&i.param.salt[0]))
	copy(salt[:],param.Salt[:])
	personal:=(*[8]byte)(unsafe.Pointer(&i.param.personal[0]))
	copy(personal[:],param.Personal[:])
	if param.Tree==nil{
		i.param.fanout=1
		i.param.depth=1
		i.Reset()
		return i
	}
	i.param.fanout=C.uint8_t(param.Tree.Fanout)
	i.param.depth=C.uint8_t(param.Tree.Max_depth)
	i.param.leaf_length=C.uint32_t(param.Tree.Max_leaf_size)
	i.param.node_offset=C.uint32_t(param.Tree.Offset)
	i.param.xof_length=C.uint16_t(param.Tree.xof_size)
	i.param.node_depth=C.uint8_t(param.Tree.Depth)
	i.param.inner_length=C.uint8_t(param.Tree.Inner_size)
	i.last_node=param.Tree.Last_node
	i.Reset()
	return i
}

func (*blake2s_info)BlockSize()int{
	return 64
}

func (i *blake2s_info)Reset(){
	if C.blake2s_init_param(&i.state,&i.param)<0{
		panic("blake2s unable to init or reset")
	}
	if i.last_node{
		i.state.last_node=1
	}
}

func (i *blake2s_info)Size()int{
	return int(i.param.digest_length)
}

func (i *blake2s_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	len_d:=i.Size()
	digest:=make([]byte,len_b+len_d)
	copy(digest,b)
	C.blake2s_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(len_d))
	return digest
}

func (i *blake2s_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2s_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
}

type blake2s_keyed_info struct{
	state C.blake2s_state
	size,key_len int
	key []byte
}

func New_Keyed(key []byte,digest_size int)hash.Hash{
	i:=new(blake2s_keyed_info)
	if digest_size>32{
		panic("blake2s output length must be 32 bytes or lower")
	}
	i.key_len=len(key)
	if i.key_len>32{
		panic("blake2s key length must be 32 bytes or lower")
	}
	i.key=key
	i.size=digest_size
	i.Reset()
	return i
}

func (*blake2s_keyed_info)BlockSize()int{
	return 64
}

func (i *blake2s_keyed_info)Reset(){
	if C.blake2s_init_key(&i.state,C.size_t(i.size),unsafe.Pointer(&i.key[0]),C.size_t(i.key_len))<0{
		panic("blake2s keyed unable to init or reset")
	}
}

func (i *blake2s_keyed_info)Size()int{
	return i.size
}

func (i *blake2s_keyed_info)Sum(b []byte)[]byte{
	len_b:=len(b)
	digest:=make([]byte,len_b+i.size)
	copy(digest,b)
	C.blake2s_final(&i.state,unsafe.Pointer(&digest[len_b]),C.size_t(i.size))
	return digest
}

func (i *blake2s_keyed_info)Write(p []byte)(int,error){
	len_p:=len(p)
	if len_p!=0{
		C.blake2s_update(&i.state,unsafe.Pointer(&p[0]),C.size_t(len_p))
	}
	return len_p,nil
} 
