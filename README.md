# blake2-go-bindings
Go bindings for the blake2 hashing algorithm, more information can be found here: https://www.blake2.net/

The C files and test files are taken from the optimized implementation found here: https://github.com/BLAKE2/BLAKE2

example:
```
package main

import(
	"fmt"
	"github.com/Tracy-Tzu/blake2-go-bindings/blake2b"
)

func main(){
	var p blake2b.Param
	data:=[]byte{1,2,3}
	p.Size=32
	h:=blake2b.New(&p)
	h.Write(data)
	fmt.Println(h.Sum(nil))
}
```
