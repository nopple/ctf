#Vulnerability
Due to an uninitialized variable in the memory allocation function, if there is only one element in the free-list, that element will be returned but not removed from the list. This means that the chunk can be returned for as many memory allocations as you want, leading to type confusion and profit.

#Relevant structures:
* `free_list_entry { word size, word unknown, free_list_entry* next }`
* `officer { word id, word status, word x, word y, officer* next }`
 * x and y are modulo 640 and 480 respectively
* `scene { word id, word inline_data[4], char* data2, word x, word y, char* data3, scene* next }`
 * Has two separately allocated buffers (data2, data3) where we have full control the size and contents

#Help from Above
Noticed that the Local Descriptor Table (bochs: info ldt) has the same logical memory space mapped to two different segments, one with RW permissions and one with RX permission

* Can write shellcode to the RW segment and jump to the RX segment so we don't need to do any real ROP (selector: 0085 - RW, selector: 0097 - RX)

#Plan of attack
Utilize the Use-After-Free vulnerability first to load shellcode into the RW segment above, and then overwrite a small amount of the stack to return into our shellcode

* Create and delete an officer to push a single chunk into the free-list
* Allocate a new officer, which will reuse the previous chunk but not remove it from the free-list
 * The officer id is at offset 0, so it will overwrite the the free-list entry size
 * Use 0xc for the size so we can overwrite all of the contents of the officer but it won't get allocated to the scene itself (0x1b allocation)
 * Set x and y both to 0 so the free-list will see the doubly-used chunk as the last one in the linked list
 * status doesn't matter for this chunk
* Next we add a scene. The contents of the fields in the scene are not so important. We will be using the two buffers it allocates since we have full control over their contents
 * For the first buffer, we will be tricking the allocator into believing that there is a large free chunk available on the heap at 0085:0000
 * It is important to notice that the allocator will read the free-list metadata from the fully-specified pointer, but will return segment:0000 to the caller, so you will always write to offset 0 although you can find appropriate metadata anywhere within the first 64k of the segment
 * Since we really only want the last two words to be 0 (null pointer to terminate the linked list), and we only need a value in the first word (free-cell size), I looked near the end of the segment, hoping there would be some extra nulls laying around. There were, so I chose 0x4688 for the segment offset.
 * For our first memory buffer then we want to write: {0xc, 0, 0x4688, 0x8f, 0, 0}. 0xc is used so we can continue to reallocate this chunk in the future (if size is too small, we won't be able to get it allocated to us). The last two words are null so that when the data is interpreted as an officer it will terminate the linked list
 * For the second memory buffer, we can now simply pass in our shellcode. Since our shellcode is > 0xc bytes, the allocator will keep looking and find our contrived free-list header in the 0x8f segment. The allocator will return 8f:0000, and the scene handler will memcpy our shellcode in
* To redirect the execution flow to our shellcode, we will need to overwrite a function pointer somewhere. I chose to do it on the stack, but any far call function pointer would do
 * For this step to work, I need to write everything that needs to be written to the stack in one go, otherwise there will be returns in between and the stack will not be fully prepared
 * My initial thought was to insert a pointer to the stack into the free-list and inject ROP in like I did to inject shellcode. This was before I knew the allocator returned xxx:0000 rather than the full pointer. Unfortunately, the stack pointer is at around 0x4700, which is too far to reach with a memcpy starting at 0x0 with the scene allocator (it limits the total allocations to 0x1000)
 * Instead, we can craft a fake officer, similar to the fake free-block, and then update it to overwrite the status, x, and y fields (offsets 2-6). We fully control the values so long as x and y are less than 640 and 480 respectively.
  * This allows a convenient ROP gadget to do retf(seg:offset) since we can use 6 bytes. Our retf target would be 0x8f:0000, so it easilly fits under the x, y maxima.
  * To update the officer, we need to meet a few constraints (some of these constraints are always required because the drawing task will happen in between commands sometimes, so the officer list will be walked)
   * First, we need to know the id value for the officer. This simply has to be any value not in use by the single other officer in our list.
   * Next, we need to ensure that the next pointer is null so that the list walking will terminate
   * Finally, since we need to overwrite 6 consecutive bytes starting with the saved value of PC, we must have the saved return address at offset 2 of the fake officer structure
  * It turns out (luckily) that the saved return value from main meets these conditions. The address of the saved PC is: ss(0x11f):47ac, so we will inject a next officer pointer of 0x11f:0x47aa
 * This is accomplished by creating another scene. The first buffer will again be 12 bytes to cover both the free-list chunk fields and the officer fields. This time we want the free-list next pointer to be null, and we'll also change the size of the free-list chunk to be small so that nothing else will overwrite it.
  * Our values are: {1, 0, 0, 0, 0x47aa, 0x1ff}
 * The second buffer for this scene plays no real purpose, so it can just be garbage data
* At this point, all we need to do is update the fake officer and it will overwrite 6 byte of the stack with the values of our choosing. From dumping memory, we see the the word at ss:0x47aa is 0x945, so we update the officer with id 0x945 with the following values: { 0x945, 0x1d26, 0x10, 0x97 }
 * 0x1d26 is a retf gadget in the executable segment (opcode 0xca)
 * 0x10 is the offset of our shellcode (the first 16 bytes were left as null to ensure that the free-list would be terminate)
 * 0x97 is the RX segment selector with our shellcode
* Now, main will return after processing the available serial data, and will begin executing our shellcode

