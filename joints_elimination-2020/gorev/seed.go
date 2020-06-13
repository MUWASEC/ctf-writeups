package main

import "fmt"
import "os"
import "math/rand"
import "strconv"
func main() {


    arg := os.Args[1]


    a := make([]byte, 35)
    ff, err := strconv.Atoi(arg)
    if err != nil {
        
     }
  
    rand.Seed(int64(ff))
    rand.Read(a)
    for _, s := range a {
        fmt.Println(s)
    }
}
