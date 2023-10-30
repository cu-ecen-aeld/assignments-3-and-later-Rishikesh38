#! /bin/sh
#Reference : The entire script is given in Lecture video : Linux System Initialization. I just understood how it works and changed the daemon name

case "$1" in
    start)
        echo "Starting aesdsocket..."
        /usr/bin/aesdchar_load
        start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
        ;;
    stop)
        echo "Stopping aesdsocket..."
        /usr/bin/aesdchar_unload
        start-stop-daemon -K -n aesdsocket
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac

exit 0