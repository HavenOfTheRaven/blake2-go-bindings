/*Copyright (c) 2025 Haven F.C. Johnson under the MIT license
test file for the go bindings for the blake2bp algorithm
*/
package blake2bp

import(
	"testing"
	"encoding/hex"
	"os"
)

func Test(t *testing.T){
	var curpos,temp_pos int=6,0
	var digest_data,key_data,sum_data []byte
	data,err:=os.ReadFile("blake2bp-kat.txt")
	if err!=nil{
		t.Fatal(err)
	}
	len_data:=len(data)
	for curpos<len_data{
		temp_pos=curpos
		for ;data[curpos]!=10;curpos+=2{}
		digest_data,err=hex.DecodeString(string(data[temp_pos:curpos]))
		if err!=nil{
			t.Fatal(err)
		}
		temp_pos=curpos+6
		curpos=temp_pos+128
		key_data,err=hex.DecodeString(string(data[temp_pos:curpos]))
		if err!=nil{
			t.Fatal(err)
		}
		h:=New_Keyed(key_data,64)
		h.Write(digest_data)
		sum_data=h.Sum(nil)
		temp_pos=curpos+7
		curpos=temp_pos+128
		if hex.EncodeToString(sum_data)!=string(data[temp_pos:curpos]){
			t.Fatal("hash mismatch")
		}
		curpos+=6
	}
}
