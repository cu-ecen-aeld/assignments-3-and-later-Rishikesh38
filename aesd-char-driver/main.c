/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes, Modified by Rishikesh Sundaragiri
 * @date 2019-10-22, Modification date : 10/28/2023
 * @copyright Copyright (c) 2019
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "linux/slab.h"
#include "linux/string.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Rishikesh Sundaragiri");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

/* Reference : https://www.coursera.org/learn/advanced-embedded-software-development/lecture/WHyp4/device-driver-file-operations*/
int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *my_dev;
    PDEBUG("open");
    my_dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = my_dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
     /* No need to do anything here as the aesd_open function didn't specifically alloc anything*/
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_buffer_entry *temp_buf = NULL;
    ssize_t entry_offset_byte_rtn = 0, buf_cnt = 0;
    struct aesd_dev *my_dev = filp->private_data;
    if(!my_dev)
    {
        return -EFAULT;
    }

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    /*
    *  Attempts to acquire a mutex lock. 
    * If the lock acquisition is interrupted (e.g., by a signal), 
    * the function returns -EINTR, which indicates an interrupted system call.
    */
    if(0 != mutex_lock_interruptible(&aesd_device.lock))
    {
        return -EINTR;
    }
    /*
    * temp_buf will point to the struct aesd_buffer_entry structure representing the position described by char_offset, or
    * NULL if this position is not available in the buffer (not enough data is written).
    */
    temp_buf = aesd_circular_buffer_find_entry_offset_for_fpos(&my_dev->buffer, *f_pos, &entry_offset_byte_rtn);
    if(temp_buf == NULL)
    {
        *f_pos = 0;
        goto error_handler;
    }
    buf_cnt = temp_buf->size - entry_offset_byte_rtn;
    //buf_cnt = (buf_cnt > count) ? count : buf_cnt;
    if(buf_cnt < count)
    {
        *f_pos += buf_cnt;
    }
    else
    {
        buf_cnt = count;
        *f_pos += count;
    }
    //*f_pos += buf_cnt;
    /* Copies data to __user buf. Here __user means that the buffer is from user space and acnnot be blindly trusted*/
    if(copy_to_user(buf, temp_buf->buffptr+entry_offset_byte_rtn, buf_cnt))
    {
        retval = -EFAULT;
        goto error_handler;
    }

    retval = buf_cnt;
error_handler:
    mutex_unlock(&aesd_device.lock);
    return retval;
}

/* Reference : Used ChatGPT in this code to kmalloc, krealloc and the '\n' line identification
 * Prompt : Gave the function signiture as input, asked to generate a code to dynalically alloc and loop for new line. 
 */
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *my_dev = NULL;                
    int null_received = 0;    
    char *return_buff = NULL;                   
    char *cb_buffer = NULL;  
	struct aesd_buffer_entry write_buf; 	
    int index = 0;
	int len_rec = 0;  
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    
    my_dev = filp->private_data;
    if(!my_dev)
    {
        return -EFAULT;
    }

   /*
    *  Attempts to acquire a mutex lock. 
    * If the lock acquisition is interrupted (e.g., by a signal), 
    * the function returns -EINTR, which indicates an interrupted system call.
    */
    if(0 != mutex_lock_interruptible(&aesd_device.lock))
    {
        return -EINTR;
    }

    if(!(my_dev->cir_buff_size))
    {
        my_dev->circular_buff = (char *)kmalloc(count, GFP_KERNEL);  // Allocate memory for circular buffer
    }
    else
    {
        my_dev->circular_buff = (char *)krealloc(my_dev->circular_buff, my_dev->cir_buff_size + count, GFP_KERNEL); // Re-Allocate memory for circular buffer
    }
    if(!(my_dev->circular_buff))
    {
        retval = -ENOMEM;
        goto error_handler;
    }
  
    cb_buffer = (my_dev->circular_buff + my_dev->cir_buff_size);  // Set circular buffer pointer
    if(copy_from_user(cb_buffer, buf, count)) // Copy data from user space to circular buffer kernel level
    {
        retval = -EFAULT;
        goto error_handler;
    }
    for(index = 0; index < count; index++)
    {
        if(cb_buffer[index] == '\n') // Check for null character
        {
            null_received = 1;
            len_rec = index+1;
            break;
        }
    }
    if(null_received)
    {
        my_dev->cir_buff_size += len_rec; // Update circular buffer size
        write_buf.buffptr = my_dev->circular_buff;
        write_buf.size = my_dev->cir_buff_size;
        return_buff = aesd_circular_buffer_add_entry(&(my_dev->buffer), &write_buf);
        if((return_buff) && (my_dev->buffer.full))
        {
            kfree(return_buff); // Free return buffer if the circular buffer is full
            return_buff = NULL;
        }
        my_dev->cir_buff_size = 0; // Reset circular buffer size
    }
    else
    {
        my_dev->cir_buff_size  += count; // Update circular buffer size
    }
    retval = count; // Set the return value to the number of bytes written
error_handler:
    mutex_unlock(&aesd_device.lock);  // Release the mutex lock
    return retval;
}


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&(aesd_device.buffer));

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    /* Clean up the Circular buffer */
    struct aesd_buffer_entry *temp_ptr = NULL;
    int index = 0;
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    AESD_CIRCULAR_BUFFER_FOREACH(temp_ptr, &aesd_device.buffer, index)
    {
      kfree(temp_ptr->buffptr);
      temp_ptr = NULL;
    }
    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
