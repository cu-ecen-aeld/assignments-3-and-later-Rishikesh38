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
#include <linux/uaccess.h>
#include "aesd_ioctl.h"

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
    /* Safety check for pointer*/
    if((!my_dev) || (!buf))
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
    if(!(temp_buf->buffptr))
    {
	    goto error_handler;
    }
    buf_cnt = temp_buf->size - entry_offset_byte_rtn;
    buf_cnt = (buf_cnt > count) ? count : buf_cnt;
    *f_pos += buf_cnt;
    /* Copies data to __user buf. Here __user means that the buffer is from user space and cannot be blindly trusted*/
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
    struct aesd_buffer_entry *return_buff = NULL;                   
    char *cb_buffer = NULL;  
	struct aesd_buffer_entry write_buf; 	
    int index = 0;
	int len_rec = 0;  
    if(!buf)
    {
	    return -EFAULT;
    }
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    
    my_dev = filp->private_data;
    if(!my_dev)
    {
        return -EFAULT;
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

        /* return_buff will have the char *buf and its size that was overwritten as out = in
         * The over written buff pointed by return_buff should be free'ed.
         * Also to maintain correct total size of circular buf, Total size - free'ed size.
        */
        return_buff = aesd_circular_buffer_add_entry(&(my_dev->buffer), &write_buf);
        my_dev->cir_buff_total_size = my_dev->cir_buff_total_size + my_dev->cir_buff_size;
        //If return_buff is not null then it points to overwritten buf that should be free'ed
        if((return_buff) && (my_dev->buffer.full))
        {
            my_dev->cir_buff_total_size = my_dev->cir_buff_total_size - return_buff->size;
            kfree(return_buff->buffptr); // Free return buffer if the circular buffer is full
            return_buff->buffptr = NULL;
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

/**
 * @brief Repositions the file offset within the AESD device file.
 *
 * This function allows repositioning the file offset within the AESD device file
 * associated with the given file pointer `filp`. It uses the provided `offset` and
 * `whence` parameters to determine the new file offset.
 *
 * @param filp    Pointer to the file structure representing the opened AESD device file.
 * @param off     The new file offset to set, which may be relative to the `whence` parameter.
 * @param whence  The reference point for repositioning the file offset, such as SEEK_SET, SEEK_CUR, or SEEK_END.
 *
 * @return The new file offset after repositioning, or an error code if repositioning fails.
 */

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
    struct aesd_dev *my_dev = filp->private_data;
    loff_t return_offset;
    /*
    * Total size of the circular buffer is passed as last parameter to the below function
    */
    return_offset =  fixed_size_llseek(filp, offset, whence, my_dev->cir_buff_total_size);
    return return_offset;
}


/**
 * @brief Adjusts the file offset for read or write operations in the AESD character device.
 *
 * This function is used to adjust the file position within the character device based on the provided
 * write command and write command offset. It performs various safety checks and ensures that the file
 * position is updated correctly.
 *
 * @param filp                Pointer to the file structure representing the opened device file.
 * @param write_cmd           The write command number to be executed.
 * @param write_cmd_offset    The offset within the write command's data buffer.
 * @return                    0 if the file offset is adjusted successfully, or an error code (negative value)
 *                            indicating the failure reason.
 */
static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    long return_value = 0;
    long f_pos = 0;
    struct aesd_dev *dev = filp->private_data;
    int index;

    /* If buffer has 10 entires then the write_cmd shouldn't be more than that*/
    if(write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
    {
        return_value = -EINVAL;
        goto exit_handler;
    }

    if(write_cmd_offset > dev->buffer.entry[write_cmd].size)
    {
        return_value = -EINVAL;
        goto exit_handler;
    }

    /*
    * blocks the process when a mutex is locked but checks for signals or interrupts. 
    * If detected, instead of just waiting for lock/blocking state it returns an error (-ERESTARTSYS), 
    * allowing the process to handle the interruption and potentially retry the operation.
    */
    if(mutex_lock_interruptible(&aesd_device.lock))
    {
        return_value = -ERESTARTSYS;
        goto exit_handler;
    }

    /* Loop through the entries of CB to find the write_cmd number*/
    for(index=0; index< write_cmd; index++)
    {
        if(dev->buffer.entry[index].size == 0)
        {
            return_value = -EINVAL;
            goto error_handler;
        }
        /* Increment the f_pos or the cursor when ever one entry is done with the size entry*/
        f_pos += dev->buffer.entry[index].size;
    }
    /* Increment the f_pos to the size of write cmd once we find the entry*/
    f_pos += write_cmd_offset;
    filp->f_pos = f_pos;
    error_handler : mutex_unlock(&aesd_device.lock);
    exit_handler : return return_value;
}

/**
 * @brief Handles IOCTL commands for the AESD character device driver.
 *
 * This function is responsible for processing IOCTL commands from user-space
 * applications to control the behavior of the AESD character device.
 *
 * @param filp A pointer to the file structure representing the opened device file.
 * @param cmd The IOCTL command to be executed.
 * @param arg The argument associated with the IOCTL command.
 * @return On failure, returns a negative error code:
 *         -ENOTTY if the IOCTL command is not recognized or invalid.
 *         -EFAULT if there is an issue copying data from user space using copy_from_user.
 */

long aesd_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long return_value;
    struct aesd_seekto buf;

    if(_IOC_TYPE(cmd) != AESD_IOC_MAGIC || _IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
    {
        return -ENOTTY;
    }
        
    switch(cmd)
    {
        case AESDCHAR_IOCSEEKTO:
        /* using copy_from_user to get the seekto parameters*/
            if(copy_from_user(&buf,(const void __user *)arg, sizeof(buf)) != 0)
            {
                return_value = -EFAULT;
            }
            else
            {
                return_value = aesd_adjust_file_offset(filp, buf.write_cmd, buf.write_cmd_offset);
            }
            break;
        default : 
            return_value = -ENOTTY;
            break;
    }

    return return_value;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =  aesd_llseek,
    .unlocked_ioctl = aesd_unlocked_ioctl,
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

    /* Init the mutex and aesd buffer*/
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
