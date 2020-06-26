#include "include/util.h"
#include "packet.h"

int cmp_lf (const void * a, const void * b) {
    return (*(double*)a) < (*(double*)b);
}

int cmp_ll (const void * a, const void * b) {
    return (*(long long*)a) < (*(long long*)b);
}

int cmp_int32 (const void * a, const void * b) {
    return (*(int32_t*)a) < (*(int32_t*)b);
}

int cmp (const void * a, const void * b) {
    tuple_t* t1 = (tuple_t*)a;
    tuple_t* t2 = (tuple_t*)b;
    
    if (t1->byte != t2->byte) {
        return t1->byte < t2->byte;
    }
    
    if (t1->key.src_ip != t2->key.src_ip) {
        return t1->key.src_ip < t2->key.src_ip;
    }
    
    if (t1->key.dst_ip != t2->key.dst_ip) {
        return t1->key.dst_ip < t2->key.dst_ip;
    }
    
    if (t1->key.src_port != t2->key.src_port) {
        return t1->key.src_port < t2->key.src_port;
    }
    
    if (t1->key.dst_port != t2->key.dst_port) {
        return t1->key.dst_port < t2->key.dst_port;
    }
    
    return t1->key.proto < t2->key.proto;
}

void quitmemory(void * pointer)
     // quit if a memory allocation failed
{
  if (pointer==NULL) exit(1);
}

long long ll_abs(long long a) {
	if (a < 0) {
		return -a;
	}
	return a;
}

