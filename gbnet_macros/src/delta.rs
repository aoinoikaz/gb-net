use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Field, Fields, Type};

fn type_ident_name(ty: &Type) -> Option<String> {
    if let Type::Path(p) = ty {
        p.path.get_ident().map(|i| i.to_string())
    } else {
        None
    }
}

fn get_field_bits(field: &Field) -> Option<usize> {
    field
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("bits"))
        .and_then(|attr| {
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

pub fn derive_network_delta_impl(input: &DeriveInput) -> TokenStream {
    let name = &input.ident;
    let delta_name = syn::Ident::new(&format!("{}Delta", name), name.span());

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(f) => &f.named,
            _ => panic!("NetworkDelta only supports named fields"),
        },
        _ => panic!("NetworkDelta only supports structs"),
    };

    let field_count = fields.len();

    // Generate delta struct fields: Option<T> per field
    let delta_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let name = f.ident.as_ref().unwrap();
            let ty = &f.ty;
            quote! { pub #name: Option<#ty> }
        })
        .collect();

    // Generate diff: compare each field
    let diff_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let name = f.ident.as_ref().unwrap();
            quote! {
                #name: if self.#name != baseline.#name {
                    Some(self.#name.clone())
                } else {
                    None
                }
            }
        })
        .collect();

    // Generate apply: update Some fields
    let apply_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let name = f.ident.as_ref().unwrap();
            quote! {
                if let Some(ref val) = delta.#name {
                    self.#name = val.clone();
                }
            }
        })
        .collect();

    // Generate BitSerialize for delta: N-bit bitmask + changed field values
    let bitmask_bits = field_count;
    let serialize_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let name = f.ident.as_ref().unwrap();
            let bits = get_field_bits(f);
            if let Some(b) = bits {
                let is_float =
                    matches!(type_ident_name(&f.ty).as_deref(), Some("f32") | Some("f64"));
                if is_float && type_ident_name(&f.ty).as_deref() == Some("f32") {
                    quote! {
                        if let Some(ref val) = self.#name {
                            writer.write_bits(val.to_bits() as u64, #b)?;
                        }
                    }
                } else if is_float {
                    quote! {
                        if let Some(ref val) = self.#name {
                            writer.write_bits(val.to_bits(), #b)?;
                        }
                    }
                } else {
                    quote! {
                        if let Some(ref val) = self.#name {
                            writer.write_bits(*val as u64, #b)?;
                        }
                    }
                }
            } else {
                quote! {
                    if let Some(ref val) = self.#name {
                        val.bit_serialize(writer)?;
                    }
                }
            }
        })
        .collect();

    let deserialize_fields: Vec<_> = fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let name = f.ident.as_ref().unwrap();
            let bits = get_field_bits(f);
            let ty = &f.ty;
            if let Some(b) = bits {
                let is_bool = type_ident_name(ty).as_deref() == Some("bool");
                let is_f32 = type_ident_name(ty).as_deref() == Some("f32");
                let is_f64 = type_ident_name(ty).as_deref() == Some("f64");
                if is_bool {
                    quote! {
                        let #name = if bitmask & (1u64 << #i) != 0 {
                            Some(reader.read_bits(#b)? != 0)
                        } else {
                            None
                        };
                    }
                } else if is_f32 {
                    quote! {
                        let #name = if bitmask & (1u64 << #i) != 0 {
                            Some(f32::from_bits(reader.read_bits(#b)? as u32))
                        } else {
                            None
                        };
                    }
                } else if is_f64 {
                    quote! {
                        let #name = if bitmask & (1u64 << #i) != 0 {
                            Some(f64::from_bits(reader.read_bits(#b)?))
                        } else {
                            None
                        };
                    }
                } else {
                    quote! {
                        let #name = if bitmask & (1u64 << #i) != 0 {
                            Some(reader.read_bits(#b)? as #ty)
                        } else {
                            None
                        };
                    }
                }
            } else {
                quote! {
                    let #name = if bitmask & (1u64 << #i) != 0 {
                        Some(::gbnet::serialize::BitDeserialize::bit_deserialize(reader)?)
                    } else {
                        None
                    };
                }
            }
        })
        .collect();

    let field_names: Vec<_> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();

    // Bitmask serialize: write presence bits
    let bitmask_serialize: Vec<_> = fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let name = f.ident.as_ref().unwrap();
            quote! {
                if self.#name.is_some() {
                    bitmask |= 1u64 << #i;
                }
            }
        })
        .collect();

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    quote! {
        #[derive(Debug, Clone, Default)]
        pub struct #delta_name {
            #(#delta_fields,)*
        }

        impl #impl_generics ::gbnet::serialize::BitSerialize for #delta_name #where_clause {
            fn bit_serialize<W: ::gbnet::serialize::bit_io::BitWrite>(&self, writer: &mut W) -> std::io::Result<()> {
                let mut bitmask: u64 = 0;
                #(#bitmask_serialize)*
                writer.write_bits(bitmask, #bitmask_bits)?;
                #(#serialize_fields)*
                Ok(())
            }
        }

        impl #impl_generics ::gbnet::serialize::BitDeserialize for #delta_name #where_clause {
            fn bit_deserialize<R: ::gbnet::serialize::bit_io::BitRead>(reader: &mut R) -> std::io::Result<Self> {
                let bitmask = reader.read_bits(#bitmask_bits)?;
                #(#deserialize_fields)*
                Ok(Self { #(#field_names,)* })
            }
        }

        impl #impl_generics ::gbnet::serialize::NetworkDelta for #name #ty_generics #where_clause {
            type Delta = #delta_name;

            fn diff(&self, baseline: &Self) -> Self::Delta {
                #delta_name {
                    #(#diff_fields,)*
                }
            }

            fn apply(&mut self, delta: &Self::Delta) {
                #(#apply_fields)*
            }
        }
    }
}
