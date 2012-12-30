/*----------------------------------------------------------------------------*/
/*
    $Desc: Portable type definitions - required for cross platform development
    $Lang: English
*/
/*----------------------------------------------------------------------------*/
#ifndef _OS_TYPES_H
#define _OS_TYPES_H

/*----------------------------------------------------------------------------*/
/* typedefs - variant A */
#ifndef u8_t
typedef unsigned char             u8_t;   /**< 8 bit unsigned integer      */
typedef unsigned short            u16_t;  /**< 16 bit unsigned integer      */
typedef unsigned long             u32_t;  /**< 32 bit unsigned integer      */
typedef signed char               s8_t;	  /**<  8 bit signed integer        */
typedef signed short              s16_t;  /**< 16 bit signed integer        */
typedef signed long               s32_t;  /**< 32 bit signed integer        */
#endif

/*----------------------------------------------------------------------------*/
/* typedefs - variant B */
#ifndef ui8
typedef unsigned char             ui8;      /**<  8 bit unsigned integer      */
typedef unsigned short            ui16;     /**< 16 bit unsigned integer      */
typedef unsigned int              ui32;     /**< 32 bit unsigned integer      */
typedef signed char               i8;		/**<  8 bit signed integer        */
typedef signed short              i16;      /**< 16 bit signed integer        */
typedef signed int                i32;      /**< 32 bit signed integer        */

/* typedefs misc */
typedef struct { i32 h; ui32 l;}  i64;      /**< 64 bit signed integer        */
typedef struct { ui32 h,l;}       ui64;     /**< 64 bit unsigned integer      */
typedef float                     fp32;     /**< 32 bit floating point number */
typedef double                    fp64;     /**< 64 bit floating point number */
typedef volatile unsigned char    io8;      /**<  8 bit IO port               */
typedef volatile unsigned short   io16;     /**< 16 bit IO port               */
typedef volatile unsigned int     io32;     /**< 32 bit IO port               */
typedef char                      b8;    	/**<  8 bit boolean value         */
typedef unsigned int		      b32;      /**< 32 bit boolean value         */
#endif

/*----------------------------------------------------------------------------*/
/* typedefs - variant C - for legacy compatibility */
#ifndef uint8
typedef unsigned char             uint8;    /**<  8 bit unsigned integer      */
typedef unsigned short            uint16;   /**< 16 bit unsigned integer      */
typedef unsigned int              uint32;   /**< 32 bit unsigned integer      */
typedef signed char               sint8;	/**<  8 bit signed integer        */
typedef signed short              sint16;   /**< 16 bit signed integer        */
typedef signed int                sint32;   /**< 32 bit signed integer        */
typedef signed char               int8;		/**<  8 bit signed integer        */
typedef signed short              int16;    /**< 16 bit signed integer        */
typedef signed int                int32;    /**< 32 bit signed integer        */
#endif

/*----------------------------------------------------------------------------*/
/* typedefs - variant D - for legacy compatibility */
#ifndef u_int8
typedef unsigned char             u_int8;   /**<  8 bit unsigned integer      */
typedef unsigned short            u_int16;  /**< 16 bit unsigned integer      */
typedef unsigned int              u_int32;  /**< 32 bit unsigned integer      */
typedef signed char               s_int8;	/**<  8 bit signed integer        */
typedef signed short              s_int16;  /**< 16 bit signed integer        */
typedef signed int                s_int32;  /**< 32 bit signed integer        */
#endif

/*----------------------------------------------------------------------------*/

#ifndef bool
typedef unsigned char bool;
#endif

#ifndef boolean
typedef unsigned char boolean;
#endif

#ifndef TRUE
#define TRUE          			  1      	/**< boolean true  */
#define FALSE                     0         /**< boolean false */
#endif

#ifndef true
#define true                      1         /**< boolean true  */
#define false                     0         /**< boolean false */
#endif

#ifndef ERROR
#define ERROR -1
#endif

#ifndef SUCCESS
#define SUCCESS 0
#endif

#ifndef _public
#define _public
#endif

#ifndef _private
#define _private static
#endif

#ifndef NULL
#define NULL	0
#endif

#define SET_BITS(data, mask)	((data)|=(mask))
#define CLEAR_BITS(data, mask)	((data)&=(~(mask)))
#define CHANGE_BITS(data, mask)	((data)^=(mask))
#define TEST_BITS(data, mask)	(((data)&(mask)) != 0)
#define SWAP(a,b)	{if (a!=b) {a^=b; b^=a; a^=b;} }

#endif
