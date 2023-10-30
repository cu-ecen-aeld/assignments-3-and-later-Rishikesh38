/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes , Modified by Rishikesh Sundaragiri
 * @date 2020-03-01 , Modified on 2023-10-21
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    // Check for null parameters
    int counter = 0;
    int buffer_position = 0;
  

    //Buffer oldest element i.e., oldest entry in the buffer is where we start our search
    buffer_position = buffer->out_offs;
    if (buffer == NULL || entry_offset_byte_rtn == NULL)
    {
	  return NULL;
    }  
    //Loop through the buffer handling the wrap around condition
    for(counter = 0; counter < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; counter++)
    {
        /*
        * If the offset is less than the size of the present entry, the requested character should be in this entry
        * If the offset is 2 and current entry size is 4 then the offset is in this entry
        * Set the entry_offset_byte_rtn to the char offset as always have the offset start from 0 for each entry
        * return the entry
        */
        if (char_offset < buffer->entry[buffer_position].size)
        {
            *entry_offset_byte_rtn = char_offset;
            return &(buffer->entry[buffer_position]);
        }
        
        /*
        * Assume the offset was 6 and the present entry was 4 so the if condition didn't sadisfy.
        * And assume the next entry is size 4.
        * We need to substract the size of that entry to offset so that when start chceking for next entry
        * we start counting the offset from 0. So if we find the offset < size of next entry we can directly 
        * equate the entry_offset_byte_rtn to char_offset as the char_offset is 0 means first element of entry.
        * 
        * Handle the wrap around condition 
        */
        char_offset -= buffer->entry[buffer_position].size;
        buffer_position = (buffer_position + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    /* If the requested character is not found, return NULL */
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    char *result = NULL;
    // Check for null pointers
    if (buffer == NULL || add_entry == NULL)
    {
        return result;
    }
    if(buffer->full)
    {
        result = (char *)buffer->entry[buffer->out_offs].buffptr;
	/* Increment the out pointer */
	buffer->out_offs++;
	/* Handle the wrap around */
	if(buffer->out_offs == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
	{
		buffer->out_offs = 0;
	}
    }
    /* Store inside the circular buffer (both buffptr and size)*/
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs++].size = add_entry->size;
    /* Handle the wrap around */
    if(buffer->in_offs == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
    {
	    buffer->in_offs = 0;
    }
						    
    /* Always check if the in and out are pointing to same element and make sure the full is set in this case*/
    if((!(buffer->full)) && (buffer->in_offs == buffer->out_offs))
    {
        buffer->full = true;
    }
    return result;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
