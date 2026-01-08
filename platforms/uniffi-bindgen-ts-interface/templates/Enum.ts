{%- macro variant_inner_fields(variant) %}
  {%- for field in variant.fields() -%}
  {% call ts::struct_field(field, 6) %}
  {%- endfor %}
{%- endmacro %}

{%- macro variant_nameless_fields(variant) -%}
[
  {%- for field in variant.fields() %}
    {{- field | typescript_type_name }}
    {%- if !loop.last %}, {% endif -%}
  {%- endfor -%}
]
{%- endmacro %}

{%- macro flat_enum(enum_def) %}
export enum {{ enum_def.name() | typescript_class_name }} {
  {%- for variant in enum_def.variants() %}
  {%- call ts::docstring(variant, 2) %}
  {%- let variant_name = variant.name() | typescript_enum_variant_name %}
  {{ variant_name }} = "{{ variant_name }}",
  {%- endfor %}
}
{%- endmacro %}

{%- macro complex_enum(enum_def) %}
export type {{ enum_def.name() | typescript_class_name }} =
  {%- for variant in enum_def.variants() %}
  {%- let variant_name = variant.name() | typescript_enum_variant_name %}
  {%- call ts::docstring(variant, 4) %}
  | {
      type_: "{{ variant_name }}";
      {%- if !variant.fields().is_empty() %}
      {%- if variant.has_nameless_fields() %}
      value: {% call variant_nameless_fields(variant) %}
      {%- else %}
      {%- call variant_inner_fields(variant) %}
      {%- endif %}
      {%- endif %}
    }
  {%- endfor %};
{%- endmacro %}

{%~ call ts::docstring(enum_def, 0) %}
{%- if enum_def.is_flat() -%}
  {%- call flat_enum(enum_def) -%}
{%- else -%}
  {%- call complex_enum(enum_def) -%}
{%- endif -%}

