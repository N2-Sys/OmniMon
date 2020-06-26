#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "include/hash.h"
#include "hash_table.h"

/************************
 *
 * private functions
 *
 ***********************/

#define NUM_ROW_FACTOR 13

unsigned int 
hashtable_hash_fcn(hashtable_t* array, hash_entry_t* f) {
    return AwareHash((unsigned char*)f->key, array->key_len,
            array->hash, array->scale, array->hardner);
}

int 
hashtable_cmp_fcn(hash_entry_t* f1, hash_entry_t* f2, int len) {
    if (memcmp(f1->key, f2->key, len)==0) {
        return 1;
    }
    return 0;
}

void 
hashtable_init_fcn(hash_entry_t* f) {
    memset(f->key, 0, f->key_len);
    memset(f->value, 0, f->value_len);
}

void 
hashtable_reset_fcn(hash_entry_t* f) {
    memset(f->key, 0, f->key_len);
    memset(f->value, 0, f->value_len);
}

void 
as_flow_travel_do_fcn(unsigned char* f, void* context) {
}

/*
 * Link the hash node to the front of the row list
 */
void hashtable_link_node(hashtable_t* array, hash_entry_t* entry) {
    int index = entry->belong;
    if (index == -1) {            // unexpected error
        fprintf(stderr, "index in as_link_node() == -1\n");
        return;
    }
    if (array->hash_list[index] != 0) {
        // add node to the front of the row list
        entry->prev = 0;
        entry->next = array->hash_list[index];
        array->hash_list[index]->prev = entry;
        array->hash_list[index] = entry;
    } else {
        // 1st node in the row list
        entry->prev = 0;
        entry->next = 0;
        array->hash_list[index] = entry;
    }
}

/*
 * Unlink the hash node from the row list
 */
void hashtable_unlink_node(hashtable_t* array, hash_entry_t* entry) {
    int index = entry->belong;
    if (index == -1) {            // unexpected error
        fprintf(stderr, "index in as_unlink_node() == -1\n");
        return;
    }
    if (entry->prev != 0) {
        // h is not the first node
        entry->prev->next = entry->next;
    } else {
        // h is the first node
        array->hash_list[index] = entry->next;
    }
    if (entry->next != 0) {
        // h is not the last node
        entry->next->prev = entry->prev;
    } 
}

void hashtable_glink_node(hashtable_t* array, hash_entry_t* entry) {
    // ghead_ should always be non-null after gunlink_node is called as it has
    // more than 1 node
    entry->gprev = 0;
    entry->gnext = array->ghead_;
    array->ghead_->gprev = entry;
    array->ghead_ = entry;
}

void hashtable_gunlink_node(hashtable_t* array, hash_entry_t* entry) {
    if (entry->gprev != 0) {            // h is not the first node
        entry->gprev->gnext = entry->gnext;
    } else {                        // h is the first node
        array->ghead_ = entry->gnext;
    }
    if (entry->gnext != 0) {            // h is not the last node
        entry->gnext->gprev = entry->gprev;
    } else {
        array->gtail_ = entry->gprev;
    }
    // note: glink_node() should be called to reset
    // the global list pointers
}

hash_entry_t* as_get_free_node(hashtable_t* array) {
    hash_entry_t* h = array->free_entry;

    if (h != NULL) {
        array->free_entry = array->free_entry->gnext;
        hashtable_init_fcn(h);
    } else {
		fprintf(stderr, "ERR: hash table exhausted %d\n", array->cur_num_entry);
		exit(-1);
    } 
    return h;
}

hash_entry_t* hashtable_find_entry(hashtable_t* array, hash_entry_t* t, int* ret_index) {
    hash_entry_t* hnode;
    int index;

    // get the row
    unsigned int hash = hashtable_hash_fcn(array, t);
    index = hash % array->num_list;
    *ret_index = index;

    // compare the hnodes along the row
    for (hnode = array->hash_list[index]; hnode != 0; hnode = hnode->next) {
        if (hashtable_cmp_fcn(hnode, t, array->key_len)) {
            // found the node
            return hnode;
        }
    }

    return NULL;
}

/************************
 *
 * functions of associative array
 *
 ***********************/

hash_entry_t* hashtable_find(hashtable_t* array, unsigned char* t, int is_create) {

    int bucket_no;
    hash_entry_t* match = hashtable_find_entry(array, (hash_entry_t*)t, &bucket_no); 

    if (match == NULL) { // key does not exist
        if (is_create) { // new added
            match = as_get_free_node(array);
            memcpy(match->key, t, array->key_len);
            match->belong = bucket_no;
            hashtable_link_node(array, match);
            array->cur_num_entry++;
        }
    }

    return match;
}

hashtable_t* hashtable_init(int max_size, int key_len, int v_len) {

    hashtable_t* ret = (hashtable_t*)calloc(1, sizeof(hashtable_t));

    ret->key_len = key_len;
    ret->value_len = v_len;
    ret->max_size = max_size;
    int num_list = calc_next_prime(max_size) * NUM_ROW_FACTOR;
    ret->num_list = num_list;

	ret->hash_list = (hash_entry_t**)calloc(num_list, sizeof(hash_entry_t*));
	if (ret->hash_list == NULL) {
		fprintf(stderr, "error: allocate hash lists\n");
		exit(-1);
	}

    ret->ghead_ = (hash_entry_t*)calloc(max_size, sizeof(hash_entry_t));
    for (int i=0; i<max_size; ++i) {
        // initialize the entry
        hashtable_init_fcn(ret->ghead_+i);
        ret->ghead_[i].key_len = key_len;
        ret->ghead_[i].value_len = v_len;
        ret->ghead_[i].belong = -1;
        ret->ghead_[i].prev = 0;
        ret->ghead_[i].next = 0;
        ret->ghead_[i].gprev = (i == 0) ? 0 : &(ret->ghead_[i-1]);
        ret->ghead_[i].gnext = (i == max_size-1) ? 0 : &(ret->ghead_[i+1]);
    }
    ret->gtail_ = &(ret->ghead_[max_size-1]);
    ret->free_entry = ret->ghead_;
    ret->slot = ret->ghead_;

    char name[] = "associative";
    int seed = 0;
    for (uint64_t i=0; i<strlen(name); i++) {
        seed += name[i];
    }
    ret->hash = GenHashSeed(seed+'h');
    ret->scale = GenHashSeed(seed+'s');
    ret->hardner = GenHashSeed(seed+'a');

    return ret;
}

int parray_byte(hashtable_t* array) {
    int admin = sizeof(hashtable_t);
    int heap_size = 0;
    int list_size = array->num_list*sizeof(hash_entry_t*);
    int slot_size = array->max_size + sizeof(hash_entry_t);

    return admin + heap_size + list_size + slot_size;
}

void hashtable_destroy(hashtable_t* array) {
    if (!array)
        return;

    if (array->slot) {
        free(array->slot);
    }

    if (array->hash_list) {
        free(array->hash_list);
    }

    free(array);
}

void hashtable_reset(hashtable_t* array) {

    hash_entry_t* h = (array->free_entry == NULL) ?
        array->gtail_ : array->free_entry->gprev;

    // free the nodes
    while (h != NULL) {
        hashtable_reset_fcn(h);
        h->belong = -1;
        h->prev = 0;
        h->next = 0;
        h = h->gprev;
    }
    // reset the free pointer
    array->free_entry = array->ghead_;
    array->cur_num_entry = 0;

    memset(array->hash_list, 0, array->num_list * sizeof(hash_entry_t*));
}

hash_entry_t* hashtable_get_all(hashtable_t* array, int* tot) {
    *tot = array->cur_num_entry;

    hash_entry_t* ret = (hash_entry_t*)calloc(*tot, sizeof(hash_entry_t));
    hash_entry_t* h = (array->free_entry == NULL) ?
        array->gtail_ : array->free_entry->gprev;

    int index = 0;
    while (h != NULL) {
        memcpy(ret+index, h, sizeof(hash_entry_t));
        index++;
        h = h->gprev;
    }

    return ret;
}
