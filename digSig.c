#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>


struct fileItems_t {
    int peHeaderLocation;
    int CoffStart;
    unsigned short Magic;
    long CertTableLOC;
    long CertLOC;
    unsigned int CertSize;
};


void help() {
    printf("Syntax: digSig [options]\n");
    printf("OPTIONS:\n");
    printf("\t-help:    print help\n");
    printf("\t-from:    file with cert\n");
    printf("\t-to:      file which you want to add a signature\n");
    printf("\t-out:     new file with added signature\n");
    printf("\n");
    printf("EXAMPLE:\n");
    printf("\tdigSig -from fileWithCert -to fileWithoutCert -out NewFileWithCert\n");
}

struct fileItems_t getFileItems(FILE *file, struct fileItems_t *fileItems) {

    fseek(file, 60, SEEK_SET);
    fread(&fileItems->peHeaderLocation, 1, 4, file);
    fileItems->CoffStart = fileItems->peHeaderLocation + 4;

    /*20 =
     * MachineType=2, NumberOfSections=2, TimeDateStamp=4, +8, SizeOfOptionalHeader=2, Characteristics=2 */
    fseek(file, fileItems->CoffStart + 20, SEEK_SET);

    fread(&fileItems->Magic, 1, 2, file);

    /* 22 =
     * MajorLinkerVersion=1, MinorLinkerVersion=1, SizeOfCode=4, SizeOfInitializedData=4, SizeOfUninitializedData=4,
     * AddressOfEntryPoint=4, BaseOfCode=4 */
    fseek(file, ftell(file) + 22, SEEK_SET);

    if (fileItems->Magic != 0x20B) {
        fseek(file, ftell(file) + 4, SEEK_SET);
    }
    if (fileItems->Magic == 0x20B) {
        fseek(file, ftell(file) + 8, SEEK_SET);
    } else {
        fseek(file, ftell(file) + 4, SEEK_SET);
    }

    /* 40 =
     * SectionAlignment=4, FileAlignment=4, MajorOperatingSystemVersion=2, MinorOperatingSystemVersion=2,
     * MajorImageVersion=2, MinorImageVersion=2, MajorSubsystemVersion=2, MinorSubsystemVersion=2, Win32VersionValue=4,
     * SizeOfImage=4, SizeOfHeaders=4, CheckSum=4, Subsystem=2, DllCharacteristics=2 */
    fseek(file, ftell(file) + 40, SEEK_SET);

    /* 32 (unsigned long long (8)) / 16 (unsigned int (4)) =
     * SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit */
    if (fileItems->Magic == 0x20B) {
        fseek(file, ftell(file) + 32, SEEK_SET);
    } else {
        fseek(file, ftell(file) + 16, SEEK_SET);
    }

    /* 40 =
     * LoaderFlags=4, NumberOfRvaAndSizes=4, ExportTableRVA=4, ExportTableSize=4, ImportTableRVA=4, ImportTableSize=4
     * ResourceTable=8, ExceptionTable=8 */
    fseek(file, ftell(file) + 40, SEEK_SET);

    fileItems->CertTableLOC = ftell(file);
    fread(&fileItems->CertLOC, 1, 4, file);
    fread(&fileItems->CertSize, 1, 4, file);

    return *fileItems;
}


void writeCert(char *srcFilePath, char *dstFilePath, char *certFilePath) {

    /* Get file items from file with cert */
    FILE *certFile = fopen(certFilePath, "rb");
    struct fileItems_t *fileItems = (struct fileItems_t *) malloc(sizeof(struct fileItems_t));
    getFileItems(certFile, fileItems);

    /* Allocate memory for cert */
    unsigned int certSize = fileItems->CertSize;
    uint8_t cert[certSize];

    /* Finish if the cert is not found */
    if (fileItems->CertLOC == 0 || certSize == 0) {
        printf("Input file Not signed!");
        exit(-1);
    }

    /* Read cert */
    fseek(certFile, fileItems->CertLOC, SEEK_SET);
    fread(&cert, 1, certSize, certFile);
    fclose(certFile);

    /* Get file items from file without cert */
    FILE *srcFile = fopen(srcFilePath, "rb");
    getFileItems(srcFile, fileItems);
    fseek(srcFile, 0, SEEK_SET);

    /* Copy file without cert */
    FILE *dstFile = fopen(dstFilePath, "wb");
    uint8_t buff[1];
    while (fread(buff, 1, 1, srcFile) > 0) {
        fwrite(buff, 1, 1, dstFile);
    }
    fseek(dstFile, 0, SEEK_END);

    /* Write cert */
    unsigned int srcFileLen = filelength(fileno(srcFile));
    fclose(srcFile);
    fwrite(&cert, 1, certSize, dstFile);
    fseek(dstFile, fileItems->CertTableLOC, SEEK_SET);
    fwrite(&srcFileLen, 1, sizeof(srcFileLen), dstFile);
    fwrite(&certSize, 1, sizeof(certSize), dstFile);
    fclose(dstFile);
}

int main(int argc, char **argv) {
    char certFilePath[100] = "";
    char srcFilePath[100] = "";
    char dstFilePath[100] = "";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0) {
            help();
            exit(0);
        } else if (strcmp(argv[i], "-from") == 0) {
            strcpy(certFilePath, (char *) argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-to") == 0) {
            strcpy(srcFilePath, (char *) argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-out") == 0) {
            strcpy(dstFilePath, (char *) argv[i + 1]);
            i++;
        }
    }

    if (certFilePath[0] == '\0' || srcFilePath[0] == '\0' || dstFilePath[0] == '\0') {
        help();
        printf("\nYou need to specify all parameters\n");
        return 0;
    }

    writeCert(srcFilePath, dstFilePath, certFilePath);

    return 0;
}
