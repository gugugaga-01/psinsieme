#ifndef OTMPSI_UTILS_COMMON_H_
#define OTMPSI_UTILS_COMMON_H_

#include <NTL/ZZ.h>

#include <string>
#include <vector>

#include "third_party/nlohmann/json.hpp"

// Define some commonly used types
typedef unsigned char uint8; // 8 bit unsigned integer
typedef unsigned int uint32; // 32 bit unsigned integer
typedef unsigned long uint64; // 64 bit unsigned integer

// Define the type of elements in the set
typedef uint32 ElementType;
// Define the type of container sizes
typedef uint32 ContainerSizeType;

// Define the maximum value for the element type
const ElementType elementTypeMax = UINT32_MAX;
// Define the maximum value for the container size type
const ContainerSizeType containerSizeTypeMax = UINT32_MAX;

// Define the number of words in an element type
const int elementTypeWords = 4;

// Enum for the role of a party in the protocol




#endif // OTMPSI_UTILS_COMMON_H_
