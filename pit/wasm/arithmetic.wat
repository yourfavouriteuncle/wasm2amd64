(module
    (func (export "main") (param $a i32) (result i32)
        (i32.add
            (i32.sub 
              (i32.const 13)
              (i32.const 10)
            )
            (i32.sub 
              (i32.const 6)
              (i32.const 3)
            )
        )
    )
)
