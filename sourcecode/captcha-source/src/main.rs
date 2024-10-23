extern crate image;
extern crate imageproc;
extern crate rand;
extern crate rusttype;
extern crate base64;
extern crate webp;

use image::{ImageBuffer, Rgb, Rgba, RgbImage, RgbaImage};
use webp::{Encoder, WebPMemory};
use imageproc::pixelops::interpolate;
use imageproc::drawing::{draw_antialiased_line_segment_mut};
use imageproc::geometric_transformations::rotate_about_center;
use imageproc::geometric_transformations::Interpolation;
use rand::{Rng};
use rusttype::*;
use std::fs;
use base64::{Engine as _, engine::{general_purpose}};
//use base64::{Engine as _, engine::{self, general_purpose}, alphabet};

fn main() {
    let base = std::env::current_dir().unwrap();

    let mut challenge_return = Vec::new();
    for i in 0..50 {
        challenge_return.push(generate_challenge(i));
    }

    let mut challenge_output = String::from("challengeArray = {} \r\n");
    for (key, challenge) in challenge_return.iter().enumerate() {
        challenge_output.push_str(&format!("challengeArray[{}] = {}\r\n", key, challenge));
    }

    let challenge_file = base.join("challenge.lua");
    fs::write(challenge_file, challenge_output).expect("write fail");
}

fn generate_challenge(_i: usize) -> String {
    //println!("debug challenge {}", _i);

    let mut rng = rand::thread_rng();

    // dimension
    let width = 160;
    let height = 160;

    // Charset
    let abc: &str = "ACDEFGHIJKLMNPQRSTUVWXYZ12345679";

    let mut img = ImageBuffer::<Rgb<u8>, _>::new(width, height);
    let colour = [26, 30, 35, 255];
    let bg_colour = image::Rgba(colour);
    for pixel in img.pixels_mut() {
    	*pixel = Rgb([bg_colour[0], bg_colour[1], bg_colour[2]]);
    }

    //println!("debug {}", 1);

    let mut colours = Vec::new();
    for _ in 0..4 {
        let mut new_colour = [rng.gen_range(90..=255), rng.gen_range(90..=255), rng.gen_range(90..=255), 255];
        new_colour[rng.gen_range(0..2)] = rng.gen_range(180..=255);

        colours.push(image::Rgba(new_colour));
    }

    // Load font file
    let select_font = pick_font();

    let font: Font = Font::try_from_bytes(select_font.font_data).unwrap();

    let font_size = rng.gen_range(select_font.min..=select_font.max) as f32;

    let fake_font_size = font_size * rng.gen_range(0.5..1.5);

    //println!("debug {}", 2);

    // Remove X exclusive line colours
    let mut line_colours = Vec::new();
    for _ in 0..2 {
        line_colours.push(colours.pop().unwrap());
    }

    // Draw a few Arcs
    let arc_max = rng.gen_range(25..=35);
    for _ in 0..arc_max {
        // using possible line colours
        let mut colour = line_colours[rng.gen_range(0..colours.len())];

        if rng.gen_range(0..100) < 25 {
            // using possible valid charset colours
            colour = colours[rng.gen_range(0..colours.len())];
        }

        let x = rng.gen_range(0..width) as i32;
        let y = rng.gen_range(0..height) as i32;
        let start_angle = rng.gen_range(0.0..360.0);
        let end_angle = rng.gen_range(0.0..360.0);
        let radius = rng.gen_range(1..width / 2) as i32;
        let thickness = rng.gen_range(1..=3);

        let colour_rgb = Rgb([colour[0], colour[1], colour[2]]);
        draw_arc(&mut img, (x, y), radius, start_angle, end_angle, colour_rgb, thickness);
    }

    // Draw a few Arcs using line colours
    /*let arc_max = rng.gen_range(15..=25);
    for _ in 0..arc_max {
        let colour = line_colours[rng.gen_range(0..colours.len())];
        let x = rng.gen_range(0..width) as i32;
        let y = rng.gen_range(0..height) as i32;
        let start_angle = rng.gen_range(0.0..360.0);
        let end_angle = rng.gen_range(0.0..360.0);
        let radius = rng.gen_range(1..width / 2) as i32;
        let thickness = rng.gen_range(1..=3);

        let colour_rgb = Rgb([colour[0], colour[1], colour[2]]);
        draw_arc(&mut img, (x, y), radius, start_angle, end_angle, colour_rgb, thickness);
    }*/

    //println!("debug {}", 3);

    // Draw lines
    /*let lines_max = rng.gen_range(15..=25);
    for _ in 0..lines_max {
        let random_colour = line_colours[rng.gen_range(0..line_colours.len())];
        //let thickness = rng.gen_range(0..2);
        let x1 = rng.gen_range(0.0..width as f32);
        let y1 = rng.gen_range(0.0..height as f32);
        let x2 = rng.gen_range(0.0..width as f32);
        let y2 = rng.gen_range(0.0..height as f32);

        let random_colour_rgb = Rgb([random_colour[0], random_colour[1], random_colour[2]]);
        draw_line_segment_mut(&mut img, (x1, y1), (x2, y2), random_colour_rgb);
    }*/

    //println!("debug {}", 4);

    // Draw fake characters
    let char_max = rng.gen_range(60..=80);
    for _ in 0..char_max {
        let random_char = abc.chars().nth(rng.gen_range(0..abc.len())).unwrap();
        let rotation = rng.gen_range(0.0..360.0);
        let random_colour = line_colours[rng.gen_range(0..line_colours.len())];

        let offset_x = rng.gen_range(5.0..(width as f32 - 5.0));
        let offset_y = rng.gen_range(5.0..(height as f32 - 5.0));


        draw_text(&mut img, &random_char.to_string(), &font, fake_font_size, random_colour, offset_x, offset_y, (rotation as f32).to_radians());
    }

    //println!("debug {}", 5);

    // Draw real characters
    let mut char_map = vec![];
    let mut x_pos = rng.gen_range(4.0..6.0);

    while x_pos < (width as f32 - (font_size * 1.5)) {
        let mut y_pos = rng.gen_range(4.0..6.0);

        while y_pos < (height as f32 - (font_size * 1.5)) {
            let y_buffer = rng.gen_range(-1.0..=8.0);
            let random_char = abc.chars().nth(rng.gen_range(0..abc.len())).unwrap();

            y_pos += y_buffer;

            let mut x_buffer = x_pos + rng.gen_range(-1.0..=8.0);
            let rotation = rng.gen_range(0.0..60.0);
            let random_colour = colours[rng.gen_range(0..colours.len())];

            //x_buffer += rng.gen_range(0.0..=1.0);
            //y_pos += rng.gen_range(0.0..=1.0);

            if x_buffer < 0.0 {
                x_buffer = 0.0;
            }
            if y_pos < 0.0 {
                y_pos = 0.0;
            }

            draw_text(&mut img, &random_char.to_string(), &font, font_size, random_colour, x_buffer, y_pos, (rotation as f32).to_radians());
            draw_text(&mut img, &random_char.to_string(), &font, font_size, random_colour, x_buffer + 1.0, y_pos, (rotation as f32).to_radians());

            //let red_pixel = Rgb([255, 0, 0]);
            //img.put_pixel(x_buffer as u32, y_pos as u32, red_pixel);

            //println!("character {} pos {}, {}", random_char.to_string(), x_buffer, y_pos);

            let rotation_offset: f32 = rng.gen_range(-8.0..=8.0);
            let offset_x = rng.gen_range(-1.0..=1.0);
            let offset_y = rng.gen_range(-1.0..=1.0);

            //let rotation_offset: f32 = 0.0;
            //let offset_x = 0.0;
            //let offset_y = 0.0;

            char_map.push( CharInfo{
                x_pos: x_buffer + offset_x,
                y_pos: y_pos + offset_y,
                font_size: font_size,
                text: random_char.to_string(),
                rotation: rotation + rotation_offset,
                xcalc: String::from(""),
                ycalc: String::from(""),
                dcalc: String::from(""),
            });

            y_pos += (font_size * 1.3) as f32;

        }

        x_pos += 4.0;
        x_pos += (font_size * 1.3) as f32;
    }

    //println!("debug {}", 6);

    // Calculate passcode
    let mut passcode = Vec::new();

    for _ in 0..6 {
        let rand_index = rng.gen_range(0..char_map.len());
        let mut rand = char_map.remove(rand_index);

        rand.x_pos -= (rand.font_size as f32) + ((9.0 - rand.font_size as f32) * 1.1);
        rand.y_pos -= rand.font_size as f32 + ((13.0 - rand.font_size as f32) * 1.1);

        if rand.x_pos < 0.0 {
            rand.x_pos = 0.0;
        }
        if rand.y_pos < 0.0 {
            rand.y_pos = 0.0;
        }

        //println!("character {} pos {}, {} rotate {}", rand.text, rand.x_pos, rand.y_pos, rand.rotation);
        //let red_pixel = Rgb([255, 0, 0]);
        //img.put_pixel(rand.x_pos as u32, rand.y_pos as u32, red_pixel);

        rand.xcalc = calc_pos(width as f32 - rand.x_pos);
        rand.ycalc = calc_pos(height as f32 - rand.y_pos);
        rand.dcalc = calc_degrees(rand.rotation);

        passcode.push(rand);
    }

    //println!("debug {}", 7);

    // Passcode input
    let mut html = String::new();
    for i in 0..passcode.len() {
        html.push_str(&format!(
            "input[name=c{}]:focus ~ .image {{
    background-position: calc({}) calc({});
    transform: rotate(calc({})) scale(6) !important;
}}\n",
            i + 1,
            passcode[i].xcalc,
            passcode[i].ycalc,
            passcode[i].dcalc
        ));
    }

    let captcha_code: String = passcode.iter().map(|code| code.text.clone()).collect();
    let compressed_html = html.split_whitespace().collect::<Vec<&str>>().join(" ");

    let image_data: &[u8] = &img.into_raw();

    let encoder = Encoder::from_rgb(image_data, width, height);
    let encoded_webp: WebPMemory = encoder.encode(70.0);

    let webp_data_slice: &[u8] = &*encoded_webp;

    let base64_encoded_webp = general_purpose::STANDARD.encode(webp_data_slice);
    //const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    //let base64_encoded_webp = CUSTOM_ENGINE.encode(webp_data_slice);

    format!(
        "\"{}*{}*{}\"\r\n",
        compressed_html,
        captcha_code,
        base64_encoded_webp
    )
}

struct CharInfo {
    x_pos: f32,
    y_pos: f32,
    font_size: f32,
    text: String,
    rotation: f32,
    xcalc: String,
    ycalc: String,
    dcalc: String,
}

#[derive(Clone)]
struct CustomFont<'a> {
    font_data: &'a [u8],
    min: u32,
    max: u32,
}

fn pick_font<'a>() -> CustomFont<'a> {
    let font = CustomFont {
        font_data: include_bytes!("font.ttf") as &[u8],
        min: 12,
        max: 17,
    };

    let plain = CustomFont {
        font_data: include_bytes!("plain.ttf") as &[u8],
        min: 13,
        max: 15,
    };

    let fonts = vec![font, plain];

    let mut rng = rand::thread_rng();
    let selected_font = fonts[rng.gen_range(0..fonts.len())].clone();

    selected_font
}

fn draw_text(img: &mut RgbImage, text: &str, font: &Font, font_size: f32, colour: Rgba<u8>, x: f32, y: f32, rotation: f32) {
    let scale = Scale { x: font_size * 1.3, y: font_size * 1.3 };
    let v_metrics = font.v_metrics(scale);

    let text_width: f32 = text
    .chars()
        .map(|c| {
            let glyph = font.glyph(c);
            let scaled_glyph = glyph.scaled(scale);
            let h_metrics = scaled_glyph.h_metrics();
            h_metrics.advance_width
        })
    .sum();

    let text_height = v_metrics.ascent - v_metrics.descent + v_metrics.line_gap;

    let original_bounding_box_size = ((text_width.powi(2) + text_height.powi(2)).sqrt()).ceil() as u32;
    let mut text_img = RgbaImage::new(original_bounding_box_size, original_bounding_box_size);

    let mut x_offset = (original_bounding_box_size as f32 - text_width) / 3.0;
    let y_offset = (original_bounding_box_size as f32 + text_height) / 3.0;

    for c in text.chars() {
        let glyph = font.glyph(c);
        let scaled_glyph = glyph.scaled(scale);
        let h_metrics = scaled_glyph.h_metrics();
        let x_position = x_offset + h_metrics.left_side_bearing;

        let positioned_glyph = scaled_glyph.positioned(Point {
        x: x_position,
        y: y_offset,
        });

        draw_glyph(&mut text_img, &positioned_glyph, colour);

        x_offset += h_metrics.advance_width;
    }

    let rotated_text_img = if rotation != 0.0 {
        rotate_about_center(&text_img, rotation, Interpolation::Bilinear, Rgba([0, 0, 0, 0]))
    } else {
        text_img
    };

    let x_min = (x - (rotated_text_img.width() as f32) / 2.0).round() as i32;
    let y_min = (y - (rotated_text_img.height() as f32) / 2.0).round() as i32;

    alpha_overlay(img, &rotated_text_img, x_min.max(0) as u32, y_min.max(0) as u32);
}

fn draw_arc(img: &mut RgbImage, centre: (i32, i32), radius: i32, start_angle: f32, end_angle: f32, colour: Rgb<u8>, thickness: i32) {
    for offset in -(thickness / 2)..=(thickness / 2) {
        let current_radius = radius + offset;
        let num_points = (
            current_radius as f32
            * (end_angle - start_angle).abs()
            * std::f32::consts::PI
            / 180.0
        ).round() as usize;
        let angle_diff = (end_angle - start_angle) / num_points as f32;

        let mut previous_point = Point{
            x: centre.0 + (radius as f32 * start_angle.to_radians().cos()).round() as i32,
            y: centre.1 - (radius as f32 * start_angle.to_radians().sin()).round() as i32
        };

        for i in 1..=num_points {
            let angle = start_angle + angle_diff * i as f32;
            let x = centre.0 + (radius as f32 * angle.to_radians().cos()).round() as i32;
            let y = centre.1 - (radius as f32 * angle.to_radians().sin()).round() as i32;
            let current_point = Point{x, y};

            draw_antialiased_line_segment_mut(
                img,
                (previous_point.x, previous_point.y),
                (current_point.x, current_point.y),
                colour,
                interpolate,
            );

            previous_point = current_point;
        }
    }
}

fn blend(src: Rgba<u8>, dst: Rgba<u8>) -> Rgba<u8> {
    let alpha_src = src[3] as f32 / 255.0;
    let alpha_dst = dst[3] as f32 / 255.0;
    let alpha_out = alpha_src + alpha_dst * (1.0 - alpha_src);

    if alpha_out == 0.0 {
        Rgba([0, 0, 0, 0])
    } else {
        let r_src = src[0] as f32 * alpha_src;
        let g_src = src[1] as f32 * alpha_src;
        let b_src = src[2] as f32 * alpha_src;
        let r_dst = dst[0] as f32 * alpha_dst * (1.0 - alpha_src);
        let g_dst = dst[1] as f32 * alpha_dst * (1.0 - alpha_src);
        let b_dst = dst[2] as f32 * alpha_dst * (1.0 - alpha_src);

        // Rgba([
        //     ((r_src + r_dst) / alpha_out) as u8,
        //     ((g_src + g_dst) / alpha_out) as u8,
        //     ((b_src + b_dst) / alpha_out) as u8,
        //     (alpha_out * 255.0) as u8,
        // ])
        Rgba([
            src[0] as u8,
            src[1] as u8,
            src[2] as u8,
            src[3] as u8,
        ])
    }
}

fn draw_glyph(img: &mut RgbaImage, glyph: &PositionedGlyph, colour: Rgba<u8>) {
    if let Some(bb) = glyph.pixel_bounding_box() {
        glyph.draw(|x, y, v| {
            let x = x as i32 + bb.min.x;
            let y = y as i32 + bb.min.y;
            if x >= 0 && y >= 0 && x < img.width() as i32 && y < img.height() as i32 {
                let pixel = img.get_pixel_mut(x as u32, y as u32);
                let src_color = Rgba([
                    colour[0],
                    colour[1],
                    colour[2],
                    (v * 255.0) as u8,
                ]);
                let blended_color = blend(src_color, *pixel);
                *pixel = blended_color;
            }
        });
    }
}

fn calc_pos(mut remain: f32) -> String {
    let mut math = String::from("0px");

    while remain > 0.0 {
        let float = rand::thread_rng().gen_range(0.0..1.0) / 3.0;
        if remain - float > 0.0 {
            remain -= float;
            math.push_str(&format!(" + {:.2}px", float));
        } else {
            math.push_str(&format!(" + {:.2}px", remain));
            break;
        }
    }

    math
    //format!("{:.2}px", remain)
}

fn calc_degrees(mut remain: f32) -> String {
    let mut degrees = String::from("0deg");

    while remain > 0.0 {
        let float = rand::thread_rng().gen_range(0.0..2.0);
        if remain - float > 0.0 {
            remain -= float;
            degrees.push_str(&format!(" - {:.2}deg", float));
        } else {
            degrees.push_str(&format!(" - {:.2}deg", remain));
            break;
        }
    }

    degrees
    //format!("{:.2}deg", remain)
}

fn alpha_overlay(dest: &mut RgbImage, src: &RgbaImage, x_offset: u32, y_offset: u32) {
    for (x, y, px_rgba) in src.enumerate_pixels() {
        let alpha = px_rgba[3] as f32 / 255.0;
        if alpha > 0.0 {
            let px_rgb = Rgb([
                px_rgba[0],
                px_rgba[1],
                px_rgba[2],
            ]);

            let x_dest = x + x_offset;
            let y_dest = y + y_offset;

            if x_dest < dest.width() && y_dest < dest.height() {
                let dest_px = dest.get_pixel_mut(x_dest, y_dest);

                if alpha >= 1.0 {
                    dest_px[0] = px_rgb[0];
                    dest_px[1] = px_rgb[1];
                    dest_px[2] = px_rgb[2];
                } else {
                    let inverse_alpha = 1.0 - alpha;
                    dest_px[0] = (dest_px[0] as f32 * inverse_alpha + px_rgb[0] as f32 * alpha).round() as u8;
                    dest_px[1] = (dest_px[1] as f32 * inverse_alpha + px_rgb[1] as f32 * alpha).round() as u8;
                    dest_px[2] = (dest_px[2] as f32 * inverse_alpha + px_rgb[2] as f32 * alpha).round() as u8;
                }
            }
        }
    }
}


