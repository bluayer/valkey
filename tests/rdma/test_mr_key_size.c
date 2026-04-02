/* test_mr_key_size.c — Check if the libfabric provider's MR keys fit in 32 bits.
 *
 * Build: gcc -o test_mr_key_size test_mr_key_size.c -lfabric
 * Usage: ./test_mr_key_size [provider]
 *        e.g. ./test_mr_key_size efa
 *             ./test_mr_key_size    (uses default provider)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>

int main(int argc, char **argv) {
    struct fi_info *hints, *fi;
    struct fid_fabric *fabric = NULL;
    struct fid_domain *domain = NULL;
    struct fid_mr *mr = NULL;
    char buf[4096] __attribute__((aligned(4096)));
    const char *provider = (argc > 1) ? argv[1] : NULL;
    int ret, exit_code = 0;

    hints = fi_allocinfo();
    if (!hints) {
        fprintf(stderr, "fi_allocinfo failed\n");
        return 1;
    }

    hints->caps = FI_MSG | FI_RMA | FI_SOURCE;
    hints->ep_attr->type = FI_EP_RDM;
    hints->mode = FI_CONTEXT2 | FI_RX_CQ_DATA;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_ENDPOINT;

    if (provider) {
        hints->fabric_attr->prov_name = strdup(provider);
    }

    ret = fi_getinfo(FI_VERSION(1, 6), NULL, NULL, 0, hints, &fi);
    fi_freeinfo(hints);
    if (ret) {
        fprintf(stderr, "fi_getinfo failed: %s\n", fi_strerror(-ret));
        return 1;
    }

    printf("Provider:      %s\n", fi->fabric_attr->prov_name);
    printf("MR mode:       0x%lx\n", (unsigned long)fi->domain_attr->mr_mode);
    printf("MR key size:   %zu bytes\n", fi->domain_attr->mr_key_size);

    if (fi->domain_attr->mr_key_size <= 8) {
        printf("\n   OK: MR key size supported by fabric wire protocol (64-bit)\n");
    } else {
        printf("\n** WARNING: MR key exceeds 64-bit — unsupported **\n");
        exit_code = 2;
    }

    /* Try to actually register memory and check the key value */
    ret = fi_fabric(fi->fabric_attr, &fabric, NULL);
    if (ret) {
        fprintf(stderr, "fi_fabric failed: %s\n", fi_strerror(-ret));
        fi_freeinfo(fi);
        return 1;
    }

    ret = fi_domain(fabric, fi, &domain, NULL);
    if (ret) {
        fprintf(stderr, "fi_domain failed: %s\n", fi_strerror(-ret));
        goto cleanup;
    }

    uint64_t access = FI_REMOTE_WRITE | FI_REMOTE_READ | FI_SEND | FI_RECV | FI_READ | FI_WRITE;
    ret = fi_mr_reg(domain, buf, sizeof(buf), access, 0, 0, 0, &mr, NULL);
    if (ret) {
        fprintf(stderr, "fi_mr_reg failed: %s\n", fi_strerror(-ret));
        goto cleanup;
    }

    uint64_t key = fi_mr_key(mr);
    printf("fi_mr_key():   0x%016lx\n", (unsigned long)key);
    printf("Fits 32-bit:   %s\n", (key <= 0xFFFFFFFF) ? "YES" : "NO");
    printf("Fits 64-bit:   YES (always)\n");

    /* Try a second registration to see if keys increment predictably */
    struct fid_mr *mr2 = NULL;
    char buf2[4096] __attribute__((aligned(4096)));
    ret = fi_mr_reg(domain, buf2, sizeof(buf2), access, 0, 0, 0, &mr2, NULL);
    if (!ret) {
        uint64_t key2 = fi_mr_key(mr2);
        printf("fi_mr_key(2):  0x%016lx\n", (unsigned long)key2);
        fi_close(&mr2->fid);
    }

cleanup:
    if (mr) fi_close(&mr->fid);
    if (domain) fi_close(&domain->fid);
    if (fabric) fi_close(&fabric->fid);
    fi_freeinfo(fi);

    return exit_code;
}
