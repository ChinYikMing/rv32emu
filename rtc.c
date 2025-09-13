#include <errno.h>
#include <fcntl.h>
#include <linux/rtc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main()
{
    int fd;
    struct rtc_time rtc_tm;
    unsigned long data;

    printf("Opening /dev/rtc0...\n");
    fd = open("/dev/rtc0", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /dev/rtc0");
        return 1;
    }

    /* Step 1. Read current RTC time */
    if (ioctl(fd, RTC_RD_TIME, &rtc_tm) == -1) {
        perror("RTC_RD_TIME ioctl failed");
        close(fd);
        return 1;
    }

    printf("Current RTC time: %04d-%02d-%02d %02d:%02d:%02d (UTC)\n",
           rtc_tm.tm_year + 1900, rtc_tm.tm_mon + 1, rtc_tm.tm_mday,
           rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

    /* Step 2. Set alarm 3 seconds from now */
    rtc_tm.tm_sec += 10;
    if (rtc_tm.tm_sec >= 60) {
        rtc_tm.tm_sec -= 60;
        rtc_tm.tm_min++;
        if (rtc_tm.tm_min >= 60) {
            rtc_tm.tm_min = 0;
            rtc_tm.tm_hour = (rtc_tm.tm_hour + 1) % 24;
        }
    }

    printf("Setting alarm for 10 seconds later...\n");
    if (ioctl(fd, RTC_ALM_SET, &rtc_tm) == -1) {
        perror("RTC_ALM_SET ioctl failed");
        close(fd);
        return 1;
    }

    /* Step 3. Enable alarm interrupt */
    if (ioctl(fd, RTC_AIE_ON, 0) == -1) {
        perror("RTC_AIE_ON ioctl failed");
        close(fd);
        return 1;
    }

    printf("Alarm enabled. Waiting for it to fire...\n");

    /* Step 4. Block until the alarm interrupt occurs */
    if (read(fd, &data, sizeof(unsigned long)) == -1) {
        perror("read() failed");
        close(fd);
        return 1;
    }

    printf(">>> Alarm Fired! <<<\n");

    /* Step 5. Disable the alarm interrupt */
    if (ioctl(fd, RTC_AIE_OFF, 0) == -1) {
        perror("RTC_AIE_OFF ioctl failed");
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
