#ifndef XZH26_COMMON_H_
#define XZH26_COMMON_H_

#include <string>
#include <vector>
#include <climits>

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long uint64;

typedef uint32 ElementType;
typedef uint32 ContainerSizeType;

const ElementType elementTypeMax = UINT32_MAX;
const ContainerSizeType containerSizeTypeMax = UINT32_MAX;

const int elementTypeWords = 4;

#endif // XZH26_COMMON_H_
