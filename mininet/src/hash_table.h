#include <stdint.h>

typedef struct Record {
	uint32_t index;
	uint32_t pkt_cnt;
	uint32_t byte_cnt;
} record_t;

typedef struct hash_entry_s {
    unsigned char key[13];
    int key_len;

    // version: 4
    // index: 4
    // pkt cnt: 4
    // byte cnt: 4
    unsigned char value[sizeof(record_t)];
    int value_len;

    int belong;      // index of list this entry belongs to

    struct hash_entry_s* prev;        // row entry list
    struct hash_entry_s* next;        
    struct hash_entry_s* gprev;        // global entry list
    struct hash_entry_s* gnext; 
} hash_entry_t;

typedef struct hashtable_s {
    int key_len;        // length of key in bits
    int value_len;
    int max_size;
	int num_list;	    // total # of lists in the table
    unsigned long long hash, scale, hardner;

	hash_entry_t **hash_list;
    hash_entry_t* slot, *ghead_, *gtail_; // global list - all allocated nodes
    hash_entry_t* free_entry;            // ptr to the available free node

    int cur_num_entry;
} hashtable_t;

hashtable_t* hashtable_init(int max_size, int key_len, int v_len); 
int hashtable_byte(hashtable_t* array);
void hashtable_destroy(hashtable_t* array);

hash_entry_t* hashtable_find(hashtable_t* array, unsigned char* key, int is_create);
void hashtable_reset(hashtable_t* array);
hash_entry_t* hashtable_get_all(hashtable_t* array, int* tot);
