/*
 * ringbuffer.hpp
 *
 * module to connect two components in same physical machine
 *
 * two types
 *     - shm based:
 *          connect two processed via user-space shared memory
 *     - kshm based:
 *          connect kernel device and process via kernel-alloc memory
 */

#define CACHE_LINE_SIZE 64
#define RB_SIZE 40000
#define RB_BATCH 50

#define START 1
#define STOP 2

//#include "alg_prob_array.h"

//#define rb_barrier() __asm__ __volatile__("": : :"memory")
//#define rb_barrier()

/*
     |---              Reader View              ---|                 |---            Writer View            ---|

|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|   |   |   |   |   |   |   |   |   | * | * | * | * | * | * | * | * | * | * | * | * | * | * | * | * |   |   |   |   |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
      |                               |           |                   |                               |       |
     global                          next        local               global                          next    local
     Read                            Read        Write               Write                           Write   Read
            <-- at most rBatch -->                                           <-- at most wBatch -->
*/

struct RBMeta {
	char cachePad0[CACHE_LINE_SIZE];
	volatile int readIndex;
	volatile int writeIndex;
	char cachePad1[CACHE_LINE_SIZE-2*sizeof(int)];
	int localWriteIndex;        // reader start
	int nextReadIndex;
	int rBatchCount;            // reader end
	char cachePad2[CACHE_LINE_SIZE-3*sizeof(int)];
	int localReadIndex;         // writer start
	int nextWriteIndex;
	int wBatchCount;            // writer end
	char cachePad3[CACHE_LINE_SIZE-3*sizeof(int)];
};

struct RingBuffer {
    char* name;
    int fd;
    unsigned long tuple_size;
    struct RBMeta* meta;
    unsigned char* data;
};

typedef struct RingBuffer ringbuffer_t;

static inline int nextVal(int x) { return (x+1) >= RB_SIZE ? 0 : x+1; }

ringbuffer_t* create_ringbuffer_shm(const char* shm_name, unsigned long tuple_size);
ringbuffer_t* connect_ringbuffer_shm(const char* shm_name, unsigned long tuple_size); 

ringbuffer_t* create_ringbuffer_kshm(unsigned char* ptr, unsigned long tuple_size); // in kernel
ringbuffer_t* connect_ringbuffer_kshm(const char* dev_name, unsigned long tuple_size); 

void close_ringbuffer_shm(ringbuffer_t* rb);
void destroy_ringbuffer_kshm(ringbuffer_t* rb);  // in kernel
void close_ringbuffer_kshm(ringbuffer_t* rb);
void start_ringbuffer_kshm(ringbuffer_t* rb);
void stop_ringbuffer_kshm(ringbuffer_t* rb);

// 0: success; otherwise: fail
int write_ringbuffer(ringbuffer_t* rb, void* data, unsigned long size);
int write_ringbuffer_block(ringbuffer_t* rb, void* data, unsigned long size);
// 0: success; otherwise: fail
int read_ringbuffer(ringbuffer_t* rb, void* data);

void flush_ringbuffer(ringbuffer_t* rb);
int  ringbuffer_size(ringbuffer_t* rb);
void read_complete_ringbuffer(ringbuffer_t* rb);
