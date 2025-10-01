export declare function customSections<A extends ArrayBufferLike = ArrayBufferLike>(a: Uint8Array<A>): Generator<{
    name: string;
    section: Uint8Array<A>;
}, void, void>;
export declare function readLEB<A extends ArrayBufferLike = ArrayBufferLike>(a: Uint8Array<A>): {
    value: bigint;
    array: Uint8Array<A>;
};
