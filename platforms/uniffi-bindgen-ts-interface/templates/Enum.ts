{%- macro variant_inner_fields(variant) %}
  {%- for field in variant.fields() -%}
  {% call ts::struct_field(field, 6) %}{% endcall %}
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
  {%- if !(variant.name() | hidden_enum_variant(enum_def.name())) %}
  {%- call ts::docstring(variant, 2) %}{% endcall %}
  {%- let variant_name = variant.name() | typescript_enum_variant_name %}
  {{ variant_name }} = "{{ variant_name }}",
  {%- endif %}
  {%- endfor %}
}
{%- endmacro %}

{%- macro complex_enum(enum_def) %}
export type {{ enum_def.name() | typescript_class_name }} =
  {%- for variant in enum_def.variants() %}
  {%- if !(variant.name() | hidden_enum_variant(enum_def.name())) %}
  {%- let variant_name = variant.name() | typescript_enum_variant_name %}
  {%- call ts::docstring(variant, 4) %}{% endcall %}
  | {
      type_: "{{ variant_name }}";
      {%- if !variant.fields().is_empty() %}
      {%- if variant.has_nameless_fields() %}
      value: {% call variant_nameless_fields(variant) %}{% endcall %}
      {%- else %}
      {%- call variant_inner_fields(variant) %}{% endcall %}
      {%- endif %}
      {%- endif %}
    }
  {%- endif %}
  {%- endfor %};
{%- endmacro %}

{%~ call ts::docstring(enum_def, 0) %}{% endcall %}
{%- if enum_def.is_flat() -%}
  {%- call flat_enum(enum_def) -%}{% endcall %}
{%- else -%}
  {%- call complex_enum(enum_def) -%}{% endcall %}
{%- endif -%}

