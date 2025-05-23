#pragma once
/* only support v4.7.6.3
int TEMP_PASSWORD_OFFSET = 0x320;
int SECRET_PASSWORD_OFFSET = 0x340;
int USER_PHONE_OFFSET = 0x620;
*/
typedef struct{
    int key;
    char value[50];
}MAGIC_DICTIONARY;

MAGIC_DICTIONARY dict[] = {
    {2, "TEMP_PASSWORD"},
    {3, "SECRET_PASSWORD"},
    {4, "COMPUTER_RESOLUTION"},
    {6, "COMPUTER_REMOTE_CODE"},
    {9, "COMPUTER_REMOTE_OWNER_PHONE"},
    {10, "TODESK_VERSION"},
};
