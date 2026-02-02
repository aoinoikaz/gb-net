use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Data, DeriveInput, Field, Fields, GenericParam, Generics, Index, Type,
};

mod delta;

// ─── Constants ─────────────────────────────────────────────────────────────

const MAX_BIT_WIDTH: usize = 64;
const BITS_PER_BYTE: usize = 8;
const DEFAULT_LEN_BITS: usize = 16;
const DEFAULT_MAX_LEN: usize = 65535;

fn add_trait_bounds(mut generics: Generics, bound: proc_macro2::TokenStream) -> Generics {
    let parsed_bound: syn::TypeParamBound = syn::parse2(bound).unwrap();
    for param in &mut generics.params {
        match param {
            GenericParam::Type(ref mut type_param) => {
                type_param.bounds.push(parsed_bound.clone());
            }
            GenericParam::Const(_) => {
                // Skip const generics — no trait bounds needed
            }
            GenericParam::Lifetime(_) => {}
        }
    }
    generics
}

// ─── Field attribute helpers ───────────────────────────────────────────────

fn should_serialize_field(field: &Field) -> bool {
    !field
        .attrs
        .iter()
        .any(|attr| attr.path().is_ident("no_serialize"))
}

fn get_field_bits(field: &Field) -> Option<usize> {
    field
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("bits"))
        .and_then(|attr| parse_lit_int(&attr.meta))
}

fn get_max_len(field: &Field, input: &DeriveInput) -> Option<usize> {
    field
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("max_len"))
        .and_then(|attr| parse_lit_int(&attr.meta))
        .or_else(|| {
            input
                .attrs
                .iter()
                .find(|attr| attr.path().is_ident("default_max_len"))
                .and_then(|attr| parse_lit_int(&attr.meta))
        })
}

fn get_with_path(field: &Field) -> Option<syn::Path> {
    field.attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("with") {
            return None;
        }
        if let syn::Meta::NameValue(syn::MetaNameValue {
            value:
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }),
            ..
        }) = &attr.meta
        {
            s.parse().ok()
        } else {
            None
        }
    })
}

fn get_skip_if(field: &Field) -> Option<syn::Expr> {
    field.attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("skip_if") {
            return None;
        }
        if let syn::Meta::NameValue(syn::MetaNameValue {
            value:
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }),
            ..
        }) = &attr.meta
        {
            s.parse().ok()
        } else {
            None
        }
    })
}

fn get_variant_id(variant: &syn::Variant) -> Option<u64> {
    variant.attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("variant_id") {
            return None;
        }
        if let syn::Meta::NameValue(syn::MetaNameValue {
            value:
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(lit),
                    ..
                }),
            ..
        }) = &attr.meta
        {
            lit.base10_parse().ok()
        } else {
            None
        }
    })
}

fn is_byte_aligned(field: &Field) -> bool {
    field
        .attrs
        .iter()
        .any(|attr| attr.path().is_ident("byte_align"))
}

fn parse_lit_int(meta: &syn::Meta) -> Option<usize> {
    match meta {
        syn::Meta::NameValue(syn::MetaNameValue {
            value:
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(lit),
                    ..
                }),
            ..
        }) => lit.base10_parse().ok(),
        _ => None,
    }
}

// ─── Type classification ───────────────────────────────────────────────────

fn type_ident_name(ty: &Type) -> Option<String> {
    if let Type::Path(p) = ty {
        p.path.get_ident().map(|i| i.to_string())
    } else {
        None
    }
}

fn is_vec_type(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.segments.iter().any(|s| s.ident == "Vec"))
}

fn is_string_type(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.segments.iter().any(|s| s.ident == "String"))
}

fn is_array_type(ty: &Type) -> bool {
    matches!(ty, Type::Array(_))
}

fn get_array_length(ty: &Type) -> Option<usize> {
    if let Type::Array(a) = ty {
        if let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(n),
            ..
        }) = &a.len
        {
            return n.base10_parse().ok();
        }
    }
    None
}

// ─── Default bits from container attrs ─────────────────────────────────────

fn get_default_bits(input: &DeriveInput) -> Vec<(String, usize)> {
    input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("default_bits"))
        .flat_map(|attr| {
            attr.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .unwrap_or_default()
            .into_iter()
            .filter_map(|meta| {
                if let syn::Meta::NameValue(nv) = meta {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(lit),
                        ..
                    }) = nv.value
                    {
                        let name = nv.path.get_ident()?.to_string();
                        Some((name, lit.base10_parse().ok()?))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        })
        .collect()
}

fn get_field_bit_width(field: &Field, defaults: &[(String, usize)]) -> usize {
    if let Some(bits) = get_field_bits(field) {
        validate_field_bits(field, bits).expect("Invalid bits attribute");
        return bits;
    }
    let name = type_ident_name(&field.ty);
    if let Some(name) = &name {
        if let Some((_, bits)) = defaults.iter().find(|(t, _)| t == name) {
            validate_field_bits(field, *bits).expect("Invalid default bits");
            return *bits;
        }
    }
    primitive_bit_capacity(&field.ty).unwrap_or(0)
}

/// Returns the native bit capacity of a primitive type, or None for non-primitives.
fn primitive_bit_capacity(ty: &Type) -> Option<usize> {
    match type_ident_name(ty).as_deref() {
        Some("bool") => Some(1),
        Some("u8") | Some("i8") => Some(8),
        Some("u16") | Some("i16") => Some(16),
        Some("u32") | Some("i32") | Some("f32") => Some(32),
        Some("u64") | Some("i64") | Some("f64") => Some(64),
        _ => None,
    }
}

fn is_bool_type(ty: &Type) -> bool {
    type_ident_name(ty).as_deref() == Some("bool")
}

fn is_float_type(ty: &Type) -> Option<&'static str> {
    match type_ident_name(ty).as_deref() {
        Some("f32") => Some("f32"),
        Some("f64") => Some("f64"),
        _ => None,
    }
}

fn is_option_type(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.segments.iter().any(|s| s.ident == "Option"))
}

fn validate_field_bits(field: &Field, bits: usize) -> syn::Result<()> {
    if bits > MAX_BIT_WIDTH {
        return Err(syn::Error::new_spanned(
            &field.ty,
            "Bits attribute exceeds maximum",
        ));
    }
    if let Some(capacity) = primitive_bit_capacity(&field.ty) {
        if is_bool_type(&field.ty) && bits != 1 {
            return Err(syn::Error::new_spanned(
                &field.ty,
                "Bool requires exactly 1 bit",
            ));
        }
        if bits > capacity {
            return Err(syn::Error::new_spanned(
                &field.ty,
                format!("Bits exceed {capacity}-bit capacity"),
            ));
        }
    }
    Ok(())
}

fn get_enum_bits(input: &DeriveInput) -> Option<usize> {
    input
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("bits"))
        .and_then(|attr| parse_lit_int(&attr.meta))
}

// ─── Len-prefix helpers (Vec / String length bits) ─────────────────────────

fn len_prefix(max_len: Option<usize>) -> (usize, proc_macro2::TokenStream) {
    if let Some(max) = max_len {
        let bits = if max == 0 {
            0
        } else {
            (u64::BITS - (max as u64).leading_zeros()) as usize
        };
        (bits, quote! { #max })
    } else {
        (DEFAULT_LEN_BITS, quote! { #DEFAULT_MAX_LEN })
    }
}

// ─── Core codegen: single-field serialize (bit mode) ───────────────────────
//
// `value_expr`  – how to access the value, e.g. `self.foo` or `*field_0`
// `label`       – debug label token for error messages
// `is_ref`      – true when the value is behind a reference (enum destructure)

fn gen_bit_serialize_field(
    field: &Field,
    value_expr: proc_macro2::TokenStream,
    label: proc_macro2::TokenStream,
    defaults: &[(String, usize)],
    input: &DeriveInput,
    is_ref: bool,
) -> proc_macro2::TokenStream {
    // #[with = "path"] overrides all default serialization
    if let Some(path) = get_with_path(field) {
        return quote! { #path::bit_serialize(&#value_expr, writer)?; };
    }

    let bits = get_field_bit_width(field, defaults);
    let max_len = get_max_len(field, input);

    let deref = if is_ref {
        quote! { * }
    } else {
        quote! {}
    };
    let iter_prefix = if is_ref {
        quote! {}
    } else {
        quote! { & }
    };

    if bits > 0 {
        // Float types need to_bits() conversion
        if let Some(float_ty) = is_float_type(&field.ty) {
            if float_ty == "f32" {
                return quote! {
                    writer.write_bits((#deref #value_expr).to_bits() as u64, #bits)?;
                };
            } else {
                return quote! {
                    writer.write_bits((#deref #value_expr).to_bits(), #bits)?;
                };
            }
        }
        // Primitive with known bit width
        quote! {
            if #bits < #MAX_BIT_WIDTH && #deref #value_expr as u64 > (1u64 << #bits) - 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Value {} exceeds {} bits for field {}", #deref #value_expr, #bits, #label),
                ));
            }
            writer.write_bits(#deref #value_expr as u64, #bits)?;
        }
    } else if is_option_type(&field.ty) {
        // Delegate to trait impl (Option<T> has 1-bit discriminant + value)
        quote! { #value_expr.bit_serialize(writer)?; }
    } else if is_vec_type(&field.ty) {
        let (len_bits, max_len_expr) = len_prefix(max_len);
        quote! {
            let max_len = #max_len_expr;
            if #value_expr.len() > max_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Vector length {} exceeds max_len {}", #value_expr.len(), max_len),
                ));
            }
            writer.write_bits(#value_expr.len() as u64, #len_bits)?;
            for item in #iter_prefix #value_expr {
                item.bit_serialize(writer)?;
            }
        }
    } else if is_string_type(&field.ty) {
        let (len_bits, max_len_expr) = len_prefix(max_len);
        quote! {
            let max_len = #max_len_expr;
            if #value_expr.len() > max_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("String length {} exceeds max_len {}", #value_expr.len(), max_len),
                ));
            }
            writer.write_bits(#value_expr.len() as u64, #len_bits)?;
            for byte in #value_expr.as_bytes() {
                writer.write_bits(*byte as u64, #BITS_PER_BYTE)?;
            }
        }
    } else if is_array_type(&field.ty) {
        quote! {
            for item in #iter_prefix #value_expr {
                item.bit_serialize(writer)?;
            }
        }
    } else {
        // Delegate to trait impl (Option, nested struct, etc.)
        quote! { #value_expr.bit_serialize(writer)?; }
    }
}

// ─── Core codegen: single-field serialize (byte mode) ──────────────────────

fn gen_byte_serialize_field(
    field: &Field,
    value_expr: proc_macro2::TokenStream,
    defaults: &[(String, usize)],
    is_ref: bool,
) -> proc_macro2::TokenStream {
    if let Some(path) = get_with_path(field) {
        return quote! { #path::byte_aligned_serialize(&#value_expr, writer)?; };
    }

    let bits = get_field_bit_width(field, defaults);
    let deref = if is_ref {
        quote! { * }
    } else {
        quote! {}
    };

    if bits > 0 {
        match type_ident_name(&field.ty).as_deref() {
            Some("u8") | Some("i8") => quote! { writer.write_u8(#deref #value_expr)?; },
            Some("u16") | Some("i16") => {
                quote! { writer.write_u16::<byteorder::LittleEndian>(#deref #value_expr as u16)?; }
            }
            Some("u32") | Some("i32") => {
                quote! { writer.write_u32::<byteorder::LittleEndian>(#deref #value_expr as u32)?; }
            }
            Some("u64") | Some("i64") => {
                quote! { writer.write_u64::<byteorder::LittleEndian>(#deref #value_expr as u64)?; }
            }
            Some("f32") => {
                quote! { writer.write_f32::<byteorder::LittleEndian>(#deref #value_expr)?; }
            }
            Some("f64") => {
                quote! { writer.write_f64::<byteorder::LittleEndian>(#deref #value_expr)?; }
            }
            Some("bool") => quote! { writer.write_u8(if #deref #value_expr { 1 } else { 0 })?; },
            _ => quote! { #value_expr.byte_aligned_serialize(writer)?; },
        }
    } else {
        quote! { #value_expr.byte_aligned_serialize(writer)?; }
    }
}

// ─── Core codegen: single-field deserialize (bit mode) ─────────────────────

fn gen_bit_deserialize_field(
    var_name: &proc_macro2::TokenStream,
    field: &Field,
    label: proc_macro2::TokenStream,
    defaults: &[(String, usize)],
    input: &DeriveInput,
) -> proc_macro2::TokenStream {
    if let Some(path) = get_with_path(field) {
        return quote! { let #var_name = #path::bit_deserialize(reader)?; };
    }

    let bits = get_field_bit_width(field, defaults);
    let max_len = get_max_len(field, input);

    if bits > 0 {
        if type_ident_name(&field.ty).as_deref() == Some("bool") {
            quote! { let #var_name = reader.read_bits(#bits)? != 0; }
        } else if let Some(float_ty) = is_float_type(&field.ty) {
            if float_ty == "f32" {
                quote! { let #var_name = f32::from_bits(reader.read_bits(#bits)? as u32); }
            } else {
                quote! { let #var_name = f64::from_bits(reader.read_bits(#bits)?); }
            }
        } else {
            quote! { let #var_name = reader.read_bits(#bits)? as _; }
        }
    } else if is_option_type(&field.ty) {
        // Delegate to trait impl
        quote! { let #var_name = ::gbnet::serialize::BitDeserialize::bit_deserialize(reader)?; }
    } else if is_vec_type(&field.ty) {
        let (len_bits, max_len_expr) = len_prefix(max_len);
        quote! {
            let len = reader.read_bits(#len_bits)? as usize;
            if len > #max_len_expr {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Vector length {} exceeds max_len {} for field {}", len, #max_len_expr, #label),
                ));
            }
            let mut #var_name = Vec::with_capacity(len);
            for _ in 0..len {
                #var_name.push(::gbnet::serialize::BitDeserialize::bit_deserialize(reader)?);
            }
        }
    } else if is_string_type(&field.ty) {
        let (len_bits, max_len_expr) = len_prefix(max_len);
        quote! {
            let len = reader.read_bits(#len_bits)? as usize;
            if len > #max_len_expr {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("String length {} exceeds max_len {} for field {}", len, #max_len_expr, #label),
                ));
            }
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(reader.read_bits(#BITS_PER_BYTE)? as u8);
            }
            let #var_name = String::from_utf8(bytes).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid UTF-8: {}", e))
            })?;
        }
    } else if is_array_type(&field.ty) {
        if let Some(array_len) = get_array_length(&field.ty) {
            quote! {
                let mut #var_name = Vec::with_capacity(#array_len);
                for _ in 0..#array_len {
                    #var_name.push(::gbnet::serialize::BitDeserialize::bit_deserialize(reader)?);
                }
                let #var_name: [_; #array_len] = #var_name.try_into().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Array length mismatch")
                })?;
            }
        } else {
            quote! { let #var_name = ::gbnet::serialize::BitDeserialize::bit_deserialize(reader)?; }
        }
    } else {
        quote! { let #var_name = ::gbnet::serialize::BitDeserialize::bit_deserialize(reader)?; }
    }
}

// ─── Core codegen: single-field deserialize (byte mode) ────────────────────

fn gen_byte_deserialize_field(
    var_name: &proc_macro2::TokenStream,
    field: &Field,
    defaults: &[(String, usize)],
) -> proc_macro2::TokenStream {
    if let Some(path) = get_with_path(field) {
        return quote! { let #var_name = #path::byte_aligned_deserialize(reader)?; };
    }

    let bits = get_field_bit_width(field, defaults);
    if bits > 0 {
        match type_ident_name(&field.ty).as_deref() {
            Some("u8") | Some("i8") => quote! { let #var_name = reader.read_u8()?; },
            Some("u16") | Some("i16") => {
                quote! { let #var_name = reader.read_u16::<byteorder::LittleEndian>()? as _; }
            }
            Some("u32") | Some("i32") => {
                quote! { let #var_name = reader.read_u32::<byteorder::LittleEndian>()? as _; }
            }
            Some("u64") | Some("i64") => {
                quote! { let #var_name = reader.read_u64::<byteorder::LittleEndian>()? as _; }
            }
            Some("f32") => {
                quote! { let #var_name = reader.read_f32::<byteorder::LittleEndian>()?; }
            }
            Some("f64") => {
                quote! { let #var_name = reader.read_f64::<byteorder::LittleEndian>()?; }
            }
            Some("bool") => quote! { let #var_name = reader.read_u8()? != 0; },
            _ => {
                quote! { let #var_name = ::gbnet::serialize::ByteAlignedDeserialize::byte_aligned_deserialize(reader)?; }
            }
        }
    } else {
        quote! { let #var_name = ::gbnet::serialize::ByteAlignedDeserialize::byte_aligned_deserialize(reader)?; }
    }
}

// ─── Byte-align wrapper ────────────────────────────────────────────────────

fn wrap_byte_align_write(
    is_bit: bool,
    is_byte_align: bool,
    inner: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    if is_bit && is_byte_align {
        quote! {
            while writer.bit_pos() % 8 != 0 { writer.write_bit(false)?; }
            #inner
        }
    } else {
        inner
    }
}

fn wrap_byte_align_read(
    is_bit: bool,
    is_byte_align: bool,
    inner: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    if is_bit && is_byte_align {
        quote! {
            while reader.bit_pos() % 8 != 0 { reader.read_bit()?; }
            #inner
        }
    } else {
        inner
    }
}

// ─── Unified field serialize codegen ───────────────────────────────────────

fn gen_field_serialize(
    field: &Field,
    value_expr: proc_macro2::TokenStream,
    label: proc_macro2::TokenStream,
    defaults: &[(String, usize)],
    input: &DeriveInput,
    is_bit: bool,
    is_ref: bool,
) -> proc_macro2::TokenStream {
    let ba = is_byte_aligned(field);
    let code = if is_bit {
        gen_bit_serialize_field(field, value_expr.clone(), label, defaults, input, is_ref)
    } else {
        gen_byte_serialize_field(field, value_expr.clone(), defaults, is_ref)
    };
    let code = wrap_byte_align_write(is_bit, ba, code);

    // Wrap with skip_if presence bit (bit mode only)
    if let Some(skip_expr) = get_skip_if(field) {
        if is_bit {
            quote! {
                if !(#skip_expr) {
                    writer.write_bit(true)?;
                    #code
                } else {
                    writer.write_bit(false)?;
                }
            }
        } else {
            code
        }
    } else {
        code
    }
}

fn gen_field_deserialize(
    var_name: &proc_macro2::TokenStream,
    field: &Field,
    label: proc_macro2::TokenStream,
    defaults: &[(String, usize)],
    input: &DeriveInput,
    is_bit: bool,
) -> proc_macro2::TokenStream {
    let ba = is_byte_aligned(field);
    let code = if is_bit {
        gen_bit_deserialize_field(var_name, field, label, defaults, input)
    } else {
        gen_byte_deserialize_field(var_name, field, defaults)
    };
    let code = wrap_byte_align_read(is_bit, ba, code);

    // Wrap with skip_if presence bit (bit mode only)
    if get_skip_if(field).is_some() && is_bit {
        quote! {
            let #var_name = if reader.read_bit()? {
                #code
                #var_name
            } else {
                Default::default()
            };
        }
    } else {
        code
    }
}

// ─── Derive entry point ────────────────────────────────────────────────────

#[proc_macro_derive(
    NetworkSerialize,
    attributes(
        no_serialize,
        bits,
        max_len,
        byte_align,
        default_bits,
        default_max_len,
        with,
        skip_if,
        variant_id
    )
)]
pub fn derive_network_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let impls = [
        gen_trait_impl(&input, name, true, true),
        gen_trait_impl(&input, name, true, false),
        gen_trait_impl(&input, name, false, true),
        gen_trait_impl(&input, name, false, false),
    ];

    let expanded = quote! { #(#impls)* };
    TokenStream::from(expanded)
}

fn gen_trait_impl(
    input: &DeriveInput,
    name: &syn::Ident,
    is_bit: bool,
    is_serialize: bool,
) -> proc_macro2::TokenStream {
    let generics = input.generics.clone();
    let body = gen_body(input, is_bit, is_serialize);

    match (is_bit, is_serialize) {
        (true, true) => {
            let generics = add_trait_bounds(generics, quote! { ::gbnet::serialize::BitSerialize });
            let (ig, tg, wc) = generics.split_for_impl();
            quote! {
                impl #ig ::gbnet::serialize::BitSerialize for #name #tg #wc {
                    fn bit_serialize<W: ::gbnet::serialize::bit_io::BitWrite>(&self, writer: &mut W) -> std::io::Result<()> { #body }
                }
            }
        }
        (true, false) => {
            let generics =
                add_trait_bounds(generics, quote! { ::gbnet::serialize::BitDeserialize });
            let (ig, tg, wc) = generics.split_for_impl();
            quote! {
                impl #ig ::gbnet::serialize::BitDeserialize for #name #tg #wc {
                    fn bit_deserialize<R: ::gbnet::serialize::bit_io::BitRead>(reader: &mut R) -> std::io::Result<Self> { #body }
                }
            }
        }
        (false, true) => {
            let generics = add_trait_bounds(
                generics,
                quote! { ::gbnet::serialize::ByteAlignedSerialize },
            );
            let (ig, tg, wc) = generics.split_for_impl();
            quote! {
                impl #ig ::gbnet::serialize::ByteAlignedSerialize for #name #tg #wc {
                    fn byte_aligned_serialize<W: std::io::Write + byteorder::WriteBytesExt>(&self, writer: &mut W) -> std::io::Result<()> { #body }
                }
            }
        }
        (false, false) => {
            let generics = add_trait_bounds(
                generics,
                quote! { ::gbnet::serialize::ByteAlignedDeserialize },
            );
            let (ig, tg, wc) = generics.split_for_impl();
            quote! {
                impl #ig ::gbnet::serialize::ByteAlignedDeserialize for #name #tg #wc {
                    fn byte_aligned_deserialize<R: std::io::Read + byteorder::ReadBytesExt>(reader: &mut R) -> std::io::Result<Self> { #body }
                }
            }
        }
    }
}

fn gen_body(input: &DeriveInput, is_bit: bool, is_serialize: bool) -> proc_macro2::TokenStream {
    match (&input.data, is_serialize) {
        (Data::Struct(data), true) => gen_struct_serialize(&data.fields, is_bit, input),
        (Data::Struct(data), false) => gen_struct_deserialize(&data.fields, is_bit, input),
        (Data::Enum(data), true) => gen_enum_serialize(data, is_bit, input),
        (Data::Enum(data), false) => gen_enum_deserialize(data, is_bit, input),
        (Data::Union(_), _) => panic!("Unions are not supported"),
    }
}

// ─── Struct serialize ──────────────────────────────────────────────────────

fn gen_struct_serialize(
    fields: &Fields,
    is_bit: bool,
    input: &DeriveInput,
) -> proc_macro2::TokenStream {
    let defaults = get_default_bits(input);
    match fields {
        Fields::Named(fields) => {
            let stmts: Vec<_> = fields
                .named
                .iter()
                .filter_map(|f| {
                    if !should_serialize_field(f) {
                        return None;
                    }
                    let name = f.ident.as_ref().unwrap();
                    let value = quote! { self.#name };
                    let label = quote! { stringify!(#name) };
                    Some(gen_field_serialize(
                        f, value, label, &defaults, input, is_bit, false,
                    ))
                })
                .collect();
            quote! { #(#stmts)* Ok(()) }
        }
        Fields::Unnamed(fields) => {
            let stmts: Vec<_> = fields
                .unnamed
                .iter()
                .enumerate()
                .filter_map(|(i, f)| {
                    if !should_serialize_field(f) {
                        return None;
                    }
                    let idx = Index::from(i);
                    let value = quote! { self.#idx };
                    let label = quote! { #i };
                    Some(gen_field_serialize(
                        f, value, label, &defaults, input, is_bit, false,
                    ))
                })
                .collect();
            quote! { #(#stmts)* Ok(()) }
        }
        Fields::Unit => quote! { Ok(()) },
    }
}

// ─── Struct deserialize ────────────────────────────────────────────────────

fn gen_struct_deserialize(
    fields: &Fields,
    is_bit: bool,
    input: &DeriveInput,
) -> proc_macro2::TokenStream {
    let defaults = get_default_bits(input);
    match fields {
        Fields::Named(fields) => {
            let (ser_names, deser_stmts): (Vec<_>, Vec<_>) = fields
                .named
                .iter()
                .filter_map(|f| {
                    if !should_serialize_field(f) {
                        return None;
                    }
                    let name = f.ident.as_ref().unwrap();
                    let var = quote! { #name };
                    let label = quote! { stringify!(#name) };
                    Some((
                        name.clone(),
                        gen_field_deserialize(&var, f, label, &defaults, input, is_bit),
                    ))
                })
                .unzip();
            let default_fields: Vec<_> = fields
                .named
                .iter()
                .filter_map(|f| {
                    if should_serialize_field(f) {
                        return None;
                    }
                    let name = f.ident.as_ref().unwrap();
                    Some(quote! { #name: Default::default() })
                })
                .collect();
            quote! {
                #(#deser_stmts)*
                Ok(Self { #(#ser_names,)* #(#default_fields,)* })
            }
        }
        Fields::Unnamed(fields) => {
            let (names, deser_stmts): (Vec<_>, Vec<_>) = fields
                .unnamed
                .iter()
                .enumerate()
                .filter_map(|(i, f)| {
                    if !should_serialize_field(f) {
                        return None;
                    }
                    let name =
                        syn::Ident::new(&format!("field_{i}"), proc_macro2::Span::call_site());
                    let var = quote! { #name };
                    let label = quote! { #i };
                    Some((
                        name,
                        gen_field_deserialize(&var, f, label, &defaults, input, is_bit),
                    ))
                })
                .unzip();
            let default_vals: Vec<_> = fields
                .unnamed
                .iter()
                .filter_map(|f| {
                    if should_serialize_field(f) {
                        return None;
                    }
                    Some(quote! { Default::default() })
                })
                .collect();
            quote! {
                #(#deser_stmts)*
                Ok(Self(#(#names,)* #(#default_vals,)*))
            }
        }
        Fields::Unit => quote! { Ok(Self) },
    }
}

// ─── Enum helpers ──────────────────────────────────────────────────────────

fn enum_variant_bits(data: &syn::DataEnum, input: &DeriveInput) -> usize {
    let count = data.variants.len();
    let min = if count <= 1 {
        // 0 or 1 variants need 0 bits, but use at least 1 for encoding
        if count == 0 {
            0
        } else {
            1
        }
    } else {
        // Integer bit math: bits needed = ceil(log2(count))
        // = 64 - leading_zeros(count - 1), handling the power-of-2 case
        (u64::BITS - (count as u64 - 1).leading_zeros()) as usize
    };
    let bits = get_enum_bits(input).unwrap_or(min);
    if bits < min {
        panic!("Enum bits ({bits}) too small for {count} variants (needs {min})");
    }
    if bits > MAX_BIT_WIDTH {
        panic!("Enum bits ({bits}) exceeds {MAX_BIT_WIDTH}");
    }
    bits
}

fn enum_write_variant_index(is_bit: bool, bits: usize, index: u64) -> proc_macro2::TokenStream {
    if is_bit {
        quote! { writer.write_bits(#index, #bits)?; }
    } else {
        quote! { writer.write_u8(#index as u8)?; }
    }
}

fn enum_read_variant_index(is_bit: bool, bits: usize) -> proc_macro2::TokenStream {
    if is_bit {
        quote! { let variant_index = reader.read_bits(#bits)?; }
    } else {
        quote! { let variant_index = reader.read_u8()? as u64; }
    }
}

// ─── Enum serialize ────────────────────────────────────────────────────────

fn gen_enum_serialize(
    data: &syn::DataEnum,
    is_bit: bool,
    input: &DeriveInput,
) -> proc_macro2::TokenStream {
    let defaults = get_default_bits(input);
    let bits = enum_variant_bits(data, input);

    // Validate variant_id: no duplicates, fits in bit width
    let mut pinned_ids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for variant in &data.variants {
        if let Some(id) = get_variant_id(variant) {
            if !pinned_ids.insert(id) {
                panic!("Duplicate #[variant_id = {}] on enum variant", id);
            }
            let max_val = if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            if id > max_val {
                panic!("#[variant_id = {}] exceeds {} bits", id, bits);
            }
        }
    }

    let arms: Vec<_> = data
        .variants
        .iter()
        .enumerate()
        .map(|(i, variant)| {
            let vname = &variant.ident;
            let vidx = get_variant_id(variant).unwrap_or(i as u64);
            let write_idx = enum_write_variant_index(is_bit, bits, vidx);

            match &variant.fields {
                Fields::Named(fields) => {
                    let names: Vec<_> = fields
                        .named
                        .iter()
                        .map(|f| f.ident.as_ref().unwrap())
                        .collect();
                    let ser_stmts: Vec<_> = fields
                        .named
                        .iter()
                        .filter_map(|f| {
                            if !should_serialize_field(f) {
                                return None;
                            }
                            let name = f.ident.as_ref().unwrap();
                            let value = quote! { #name };
                            let label = quote! { stringify!(#name) };
                            Some(gen_field_serialize(
                                f, value, label, &defaults, input, is_bit, true,
                            ))
                        })
                        .collect();
                    quote! {
                        Self::#vname { #(#names),* } => {
                            #write_idx
                            #(#ser_stmts)*
                            Ok(())
                        },
                    }
                }
                Fields::Unnamed(fields) => {
                    let names: Vec<_> = (0..fields.unnamed.len())
                        .map(|i| {
                            syn::Ident::new(&format!("field_{i}"), proc_macro2::Span::call_site())
                        })
                        .collect();
                    let ser_stmts: Vec<_> = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .filter_map(|(i, f)| {
                            if !should_serialize_field(f) {
                                return None;
                            }
                            let name = &names[i];
                            let value = quote! { #name };
                            let label = quote! { #i };
                            Some(gen_field_serialize(
                                f, value, label, &defaults, input, is_bit, true,
                            ))
                        })
                        .collect();
                    quote! {
                        Self::#vname(#(#names),*) => {
                            #write_idx
                            #(#ser_stmts)*
                            Ok(())
                        },
                    }
                }
                Fields::Unit => quote! {
                    Self::#vname => { #write_idx Ok(()) },
                },
            }
        })
        .collect();

    quote! { match self { #(#arms)* } }
}

// ─── Enum deserialize ──────────────────────────────────────────────────────

fn gen_enum_deserialize(
    data: &syn::DataEnum,
    is_bit: bool,
    input: &DeriveInput,
) -> proc_macro2::TokenStream {
    let defaults = get_default_bits(input);
    let bits = enum_variant_bits(data, input);
    let read_idx = enum_read_variant_index(is_bit, bits);

    let arms: Vec<_> = data
        .variants
        .iter()
        .enumerate()
        .map(|(i, variant)| {
            let vname = &variant.ident;
            let vidx = get_variant_id(variant).unwrap_or(i as u64);

            match &variant.fields {
                Fields::Named(fields) => {
                    let (names, stmts): (Vec<_>, Vec<_>) = fields
                        .named
                        .iter()
                        .filter_map(|f| {
                            if !should_serialize_field(f) {
                                return None;
                            }
                            let name = f.ident.as_ref().unwrap();
                            let var = quote! { #name };
                            let label = quote! { stringify!(#name) };
                            Some((
                                name.clone(),
                                gen_field_deserialize(&var, f, label, &defaults, input, is_bit),
                            ))
                        })
                        .unzip();
                    let default_fields: Vec<_> = fields
                        .named
                        .iter()
                        .filter_map(|f| {
                            if should_serialize_field(f) {
                                return None;
                            }
                            let name = f.ident.as_ref().unwrap();
                            Some(quote! { #name: Default::default() })
                        })
                        .collect();
                    quote! {
                        #vidx => {
                            #(#stmts)*
                            Ok(Self::#vname { #(#names,)* #(#default_fields,)* })
                        },
                    }
                }
                Fields::Unnamed(fields) => {
                    let (names, stmts): (Vec<_>, Vec<_>) = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .filter_map(|(i, f)| {
                            if !should_serialize_field(f) {
                                return None;
                            }
                            let name = syn::Ident::new(
                                &format!("field_{i}"),
                                proc_macro2::Span::call_site(),
                            );
                            let var = quote! { #name };
                            let label = quote! { #i };
                            Some((
                                name,
                                gen_field_deserialize(&var, f, label, &defaults, input, is_bit),
                            ))
                        })
                        .unzip();
                    let default_vals: Vec<_> = fields
                        .unnamed
                        .iter()
                        .filter_map(|f| {
                            if should_serialize_field(f) {
                                return None;
                            }
                            Some(quote! { Default::default() })
                        })
                        .collect();
                    quote! {
                        #vidx => {
                            #(#stmts)*
                            Ok(Self::#vname(#(#names,)* #(#default_vals,)*))
                        },
                    }
                }
                Fields::Unit => quote! {
                    #vidx => Ok(Self::#vname),
                },
            }
        })
        .collect();

    quote! {
        #read_idx
        match variant_index {
            #(#arms)*
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unknown variant index")),
        }
    }
}

// ─── NetworkDelta derive ────────────────────────────────────────────────────

#[proc_macro_derive(NetworkDelta, attributes(bits))]
pub fn derive_network_delta(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    TokenStream::from(delta::derive_network_delta_impl(&input))
}
