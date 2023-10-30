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
        goto error_handler;
    }
    buf_cnt = temp_buf->size - entry_offset_byte_rtn;
    buf_cnt = (buf_cnt > count) ? count : buf_cnt;
    *f_pos += buf_cnt;
    /* Copies data to __user buf. Here __user means that the buffer is from user space and acnnot be blindly trusted*/
    if(copy_to_user(buf, temp_buff->buffptr+entry_offset_byte_rtn, buf_cnt))
    {
        retval = -EFAULT;
        goto error_handler;
    }

    retval = buf_cnt;
error_handler:
    *f_pos = 0;
    mutex_unlock(&aesd_device.lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{

    ssize_t retval = 0;
    char *return_buff;
    struct aesd_buffer_entry write_buf;
    bool new_line_received = false;
    uint32_t line_length = 0;
    struct aesd_dev *my_dev;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    my_dev = filp->private_data;
    if(!my_dev)
    {
        return -EFAULT;
    }
    /* dynamically a buffer temporarily that can be used to store user buffer data */
    char *buffr = (char *)kmalloc(count, GFP_KERNEL);
    if(NULL == buffr)
    {
        retval = -ENOMEM;
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

    /* copy the data from user buffer to kernel buffer*/
    if(copy_from_user(buffr, buf, count))
    {
        retval = -EFAULT;
        goto wr_error_handler;
    }

    /* Keep looping to check the '\n'*/
    for(index = 0; index < count; index++)
    {
        if(buffr[index] == '\n')
        {
            new_line_received = true;
            line_length = index+1;
            break;
        }
    }
    /* alloc for the first time*/
    if(0 == my_dev->cir_buff_size)
    {
        my_dev->circular_buff = (char *)kmalloc(count, GFP_KERNEL);
        if(NULL == my_dev->circular_buff)
        {
            retval = -ENOMEM;
            goto wr_error_handler;
        }
        /* Copy from kernel temp buffer to dev*/
        memcpy(my_dev->circular_buff, buffr, count);
        my_dev->cir_buff_size += count;
    }
    /* Space not enough and need to realloc */
    else
    {
        /* If the '\n' is received then realloc only the received size, else do the count size*/
        if(new_line_received)
        {
            my_dev->circular_buff = (char *)krealloc(my_dev->circular_buff, my_dev->cir_buff_size + line_length, GFP_KERNEL);
            if(NULL == my_dev->circular_buff)
            {
                retval = -ENOMEM;
                goto wr_error_handler;
            }
            /* Copy from kernel temp buffer to dev*/
            memcpy(my_dev->circular_buff + my_dev->cir_buff_size, buffr, line_length);
            my_dev->cir_buff_size += line_length;
        }
        else
        {
            my_dev->circular_buff = (char *)krealloc(my_dev->circular_buff, my_dev->cir_buff_size + count, GFP_KERNEL);
            if(NULL == my_dev->circular_buff)
            {
                retval = -ENOMEM;
                goto wr_error_handler;
            }
            /* Copy from kernel temp buffer to dev*/
            memcpy(my_dev->circular_buff + my_dev->cir_buff_size, buffr, count);
            my_dev->cir_buff_size += count;            
        }
    }
    /* As the line is completed, need to be added to the circular buffer*/
    if(new_line_received)
    {
        write_buf.buffptr = my_dev->circular_buff;
        write_buf.size = my_dev->cir_buff_size;
        return_buff = aesd_circular_buffer_add_entry(&my_dev->buffer, &write_buf);
        /* Handing overwritten case below*/
        if(return_buff != NULL )
        {
            kfree(return_buff);
        }
        /* Free the size*/
        my_dev->cir_buff_size = 0;
    }
    retval = count;
    wr_error_handler : kfree(buffr);
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