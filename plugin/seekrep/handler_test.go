package seekrep

import (
	"fmt"
	"testing"
)

func TestRemoveSeekrepPrefix(t *testing.T) {
	result := RemoveSeekrepPrefix("seekrep999-mynamespace2-myapp-myversion-nro.svc.cluster.local")
	fmt.Println(result)
}
