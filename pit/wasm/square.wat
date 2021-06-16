(module
    (func $square (param $i i32) (result i32)
        (i32.mul
            (get_local $i)
            (get_local $i)
        )
    )

    (func (export "main") (param $a i32) (result i32)
        (call $square 
            (get_local $a)
        )
    )
)
