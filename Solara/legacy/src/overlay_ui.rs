use crate::esp_data::{EspData, EspConfig, PlayerData, GadgetData, ObjectiveData, Team, PlayerState, GadgetType, ObjectiveType, Vector3};
use crate::renderer::Vertex;

#[derive(Debug, Clone)]
pub struct Vector2 {
    pub x: f32,
    pub y: f32,
}

pub struct OverlayUI {
    vertices: Vec<Vertex>,
    indices: Vec<u16>,
    screen_width: f32,
    screen_height: f32,
}

impl OverlayUI {
    pub fn new() -> Self {
        Self {
            vertices: Vec::new(),
            indices: Vec::new(),
            screen_width: 1920.0, // Default, will be updated
            screen_height: 1080.0,
        }
    }

    pub fn update(&mut self, esp_data: &Option<EspData>, esp_config: &EspConfig) {
        // Clear previous frame data
        self.vertices.clear();
        self.indices.clear();

        if let Some(data) = esp_data {
            // Render players
            for player in &data.players {
                self.render_player(player, esp_config);
            }

            // Render gadgets
            for gadget in &data.gadgets {
                self.render_gadget(gadget, esp_config);
            }

            // Render objectives
            for objective in &data.objectives {
                self.render_objective(objective, esp_config);
            }

            // Render game state info
            self.render_game_state(&data.game_state, esp_config);
        }
    }

    pub fn generate_render_data(&self) -> (Vec<Vertex>, Vec<u16>) {
        (self.vertices.clone(), self.indices.clone())
    }

    fn render_player(&mut self, player: &PlayerData, config: &EspConfig) {
        // Skip if player is too far away
        if player.distance > config.max_distance {
            return;
        }

        // Skip if visibility check is enabled and player is not visible
        if config.visibility_check && !player.visible {
            return;
        }

        // Convert 3D position to 2D screen coordinates
        let screen_pos = self.world_to_screen(&player.position);
        if screen_pos.is_none() {
            return;
        }
        let screen_pos = screen_pos.unwrap();

        // Render skeleton
        if config.skeleton_enabled && !player.bones.is_empty() {
            let color = config.get_color_rgba(&config.skeleton_color);
            self.render_skeleton(&player.bones, color);
        }

        // Render bounding box
        if config.box_enabled {
            let color = config.get_color_rgba(&config.box_color);
            self.render_bounding_box(&screen_pos, 50.0, 80.0, color);
        }

        // Render health bar
        if config.health_enabled {
            let color = config.get_color_rgba(&config.health_color);
            self.render_health_bar(&screen_pos, player.health, color);
        }

        // Render name
        if config.name_enabled {
            let color = config.get_color_rgba(&config.name_color);
            self.render_text(&screen_pos, &player.name, color);
        }

        // Render distance
        if config.distance_enabled {
            let color = config.get_color_rgba(&config.distance_color);
            let distance_text = format!("{:.0}m", player.distance);
            let distance_pos = Vector2 { x: screen_pos.x, y: screen_pos.y + 20.0 };
            self.render_text(&distance_pos, &distance_text, color);
        }

        // Render head dot
        if config.head_dot_enabled {
            let color = config.get_color_rgba(&config.head_dot_color);
            let head_pos = Vector2 { x: screen_pos.x, y: screen_pos.y - 40.0 };
            self.render_dot(&head_pos, 3.0, color);
        }

        // Render snaplines
        if config.snaplines_enabled {
            let color = config.get_color_rgba(&config.snaplines_color);
            let center = Vector2 { x: self.screen_width / 2.0, y: self.screen_height };
            self.render_line(&center, &screen_pos, color);
        }
    }

    fn render_gadget(&mut self, gadget: &GadgetData, config: &EspConfig) {
        // Skip if gadget is too far away
        if gadget.distance > config.max_distance {
            return;
        }

        let screen_pos = self.world_to_screen(&gadget.position);
        if screen_pos.is_none() {
            return;
        }
        let screen_pos = screen_pos.unwrap();

        let (enabled, color) = match gadget.gadget_type {
            GadgetType::Trap => (config.traps_enabled, config.get_color_rgba(&config.traps_color)),
            GadgetType::Camera => (config.cameras_enabled, config.get_color_rgba(&config.cameras_color)),
            GadgetType::Drone => (config.drones_enabled, config.get_color_rgba(&config.drones_color)),
            GadgetType::Destructible => (config.destructibles_enabled, config.get_color_rgba(&config.destructibles_color)),
            GadgetType::Breaching => (config.breaching_enabled, config.get_color_rgba(&config.breaching_color)),
            GadgetType::Throwable => (config.throwables_enabled, config.get_color_rgba(&config.throwables_color)),
            GadgetType::Utility => (config.utility_enabled, config.get_color_rgba(&config.utility_color)),
            _ => (false, [1.0, 1.0, 1.0, 1.0]),
        };

        if enabled {
            // Render gadget as a small box
            self.render_bounding_box(&screen_pos, 15.0, 15.0, color);
            
            // Render gadget type indicator
            let gadget_name = match gadget.gadget_type {
                GadgetType::Trap => "TRAP",
                GadgetType::Camera => "CAM",
                GadgetType::Drone => "DRONE",
                GadgetType::Destructible => "DEST",
                GadgetType::Breaching => "BREACH",
                GadgetType::Throwable => "THROW",
                GadgetType::Utility => "UTIL",
                _ => "UNK",
            };
            
            let mut text_pos = screen_pos;
            text_pos.y += 20.0;
            self.render_text(&text_pos, gadget_name, color);
        }
    }

    fn render_objective(&mut self, objective: &ObjectiveData, config: &EspConfig) {
        let screen_pos = self.world_to_screen(&objective.position);
        if screen_pos.is_none() {
            return;
        }
        let screen_pos = screen_pos.unwrap();

        let (enabled, color, name) = match objective.objective_type {
            ObjectiveType::Bomb => (config.bomb_sites_enabled, config.get_color_rgba(&config.bomb_sites_color), "BOMB"),
            ObjectiveType::Hostage => (config.hostages_enabled, config.get_color_rgba(&config.hostages_color), "HOSTAGE"),
            ObjectiveType::SecureArea => (config.objectives_enabled, config.get_color_rgba(&config.objectives_color), "SECURE"),
        };

        if enabled {
            // Render objective as a larger box
            self.render_bounding_box(&screen_pos, 30.0, 30.0, color);
            
            // Render objective name
            let mut text_pos = screen_pos;
            text_pos.y += 40.0;
            self.render_text(&text_pos, name, color);

            // Render timer if available
            if let Some(timer) = objective.timer {
                let timer_text = format!("{:.1}s", timer);
                text_pos.y += 15.0;
                self.render_text(&text_pos, &timer_text, color);
            }
        }
    }

    fn render_game_state(&mut self, _game_state: &crate::esp_data::GameState, _config: &EspConfig) {
        // Game state rendering could include:
        // - Round timer
        // - Bomb timer
        // - Score display
        // - Game mode info
        // For now, this is left as a placeholder
    }

    fn render_skeleton(&mut self, bones: &[Vector3], color: [f32; 4]) {
        // Simplified skeleton rendering - connects major bone points
        if bones.len() < 15 {
            return; // Need minimum bone count for skeleton
        }

        // Define bone connections (simplified)
        let bone_connections = [
            (0, 1),   // Head to neck
            (1, 2),   // Neck to spine
            (2, 3),   // Spine to pelvis
            (1, 4),   // Neck to left shoulder
            (4, 5),   // Left shoulder to left elbow
            (5, 6),   // Left elbow to left hand
            (1, 7),   // Neck to right shoulder
            (7, 8),   // Right shoulder to right elbow
            (8, 9),   // Right elbow to right hand
            (3, 10),  // Pelvis to left hip
            (10, 11), // Left hip to left knee
            (11, 12), // Left knee to left foot
            (3, 13),  // Pelvis to right hip
            (13, 14), // Right hip to right knee
            (14, 15), // Right knee to right foot
        ];

        for (start_idx, end_idx) in bone_connections.iter() {
            if *start_idx < bones.len() && *end_idx < bones.len() {
                let start_pos = self.world_to_screen(&bones[*start_idx]);
                let end_pos = self.world_to_screen(&bones[*end_idx]);

                if let (Some(start), Some(end)) = (start_pos, end_pos) {
                    self.render_line(&start, &end, color);
                }
            }
        }
    }

    fn render_bounding_box(&mut self, center: &Vector2, width: f32, height: f32, color: [f32; 4]) {
        let half_width = width / 2.0;
        let half_height = height / 2.0;

        // Define box corners
        let top_left = Vector2 { x: center.x - half_width, y: center.y - half_height };
        let top_right = Vector2 { x: center.x + half_width, y: center.y - half_height };
        let bottom_left = Vector2 { x: center.x - half_width, y: center.y + half_height };
        let bottom_right = Vector2 { x: center.x + half_width, y: center.y + half_height };

        // Render box edges
        self.render_line(&top_left, &top_right, color);
        self.render_line(&top_right, &bottom_right, color);
        self.render_line(&bottom_right, &bottom_left, color);
        self.render_line(&bottom_left, &top_left, color);
    }

    fn render_health_bar(&mut self, center: &Vector2, health: u32, color: [f32; 4]) {
        let bar_width = 50.0;
        let bar_height = 4.0;
        let health_percentage = (health as f32 / 100.0).min(1.0);

        // Background bar (dark)
        let bg_color = [0.2, 0.2, 0.2, 0.8];
        let bg_pos = Vector2 { x: center.x - bar_width / 2.0, y: center.y - 50.0 };
        self.render_filled_rect(&bg_pos, bar_width, bar_height, bg_color);

        // Health bar (colored based on health)
        let health_color = if health > 75 {
            [0.0, 1.0, 0.0, 1.0] // Green
        } else if health > 25 {
            [1.0, 1.0, 0.0, 1.0] // Yellow
        } else {
            [1.0, 0.0, 0.0, 1.0] // Red
        };

        let health_width = bar_width * health_percentage;
        self.render_filled_rect(&bg_pos, health_width, bar_height, health_color);
    }

    fn render_text(&mut self, _position: &Vector2, _text: &str, _color: [f32; 4]) {
        // Text rendering would require a font system
        // For now, this is a placeholder - could be implemented with:
        // - Bitmap fonts
        // - SDF (Signed Distance Field) fonts
        // - Integration with a text rendering library
    }

    fn render_dot(&mut self, center: &Vector2, radius: f32, color: [f32; 4]) {
        // Render a simple dot as a small filled circle (approximated with triangles)
        let segments = 8;
        let center_vertex_idx = self.vertices.len() as u16;

        // Add center vertex
        self.vertices.push(Vertex {
            position: [center.x, center.y, 0.0],
            color,
        });

        // Add circle vertices
        for i in 0..segments {
            let angle = (i as f32 / segments as f32) * 2.0 * std::f32::consts::PI;
            let x = center.x + radius * angle.cos();
            let y = center.y + radius * angle.sin();

            self.vertices.push(Vertex {
                position: [x, y, 0.0],
                color,
            });

            // Add triangle indices
            let current_idx = center_vertex_idx + 1 + i as u16;
            let next_idx = center_vertex_idx + 1 + ((i + 1) % segments) as u16;

            self.indices.push(center_vertex_idx);
            self.indices.push(current_idx);
            self.indices.push(next_idx);
        }
    }

    fn render_line(&mut self, start: &Vector2, end: &Vector2, color: [f32; 4]) {
        let line_width = 1.0;
        
        // Calculate perpendicular vector for line width
        let dx = end.x - start.x;
        let dy = end.y - start.y;
        let length = (dx * dx + dy * dy).sqrt();
        
        if length < 0.001 {
            return; // Skip zero-length lines
        }
        
        let perp_x = -dy / length * line_width * 0.5;
        let perp_y = dx / length * line_width * 0.5;

        let start_idx = self.vertices.len() as u16;

        // Add line vertices (quad)
        self.vertices.push(Vertex {
            position: [start.x + perp_x, start.y + perp_y, 0.0],
            color,
        });
        self.vertices.push(Vertex {
            position: [start.x - perp_x, start.y - perp_y, 0.0],
            color,
        });
        self.vertices.push(Vertex {
            position: [end.x - perp_x, end.y - perp_y, 0.0],
            color,
        });
        self.vertices.push(Vertex {
            position: [end.x + perp_x, end.y + perp_y, 0.0],
            color,
        });

        // Add triangle indices for quad
        self.indices.push(start_idx);
        self.indices.push(start_idx + 1);
        self.indices.push(start_idx + 2);
        
        self.indices.push(start_idx);
        self.indices.push(start_idx + 2);
        self.indices.push(start_idx + 3);
    }

    fn render_filled_rect(&mut self, position: &Vector2, width: f32, height: f32, color: [f32; 4]) {
        let start_idx = self.vertices.len() as u16;

        // Add rectangle vertices
        self.vertices.push(Vertex {
            position: [position.x, position.y, 0.0],
            color,
        });
        self.vertices.push(Vertex {
            position: [position.x + width, position.y, 0.0],
            color,
        });
        self.vertices.push(Vertex {
            position: [position.x + width, position.y + height, 0.0],
            color,
        });
        self.vertices.push(Vertex {
            position: [position.x, position.y + height, 0.0],
            color,
        });

        // Add triangle indices for rectangle
        self.indices.push(start_idx);
        self.indices.push(start_idx + 1);
        self.indices.push(start_idx + 2);
        
        self.indices.push(start_idx);
        self.indices.push(start_idx + 2);
        self.indices.push(start_idx + 3);
    }

    fn world_to_screen(&self, world_pos: &Vector3) -> Option<Vector2> {
        // PLACEHOLDER: 3D to 2D projection
        // In a real implementation, this would:
        // 1. Get the game's view matrix and projection matrix
        // 2. Transform world coordinates to screen coordinates
        // 3. Handle clipping and depth testing
        
        // For now, return a simple mapping for demonstration
        Some(Vector2 {
            x: (world_pos.x * 10.0 + self.screen_width / 2.0).clamp(0.0, self.screen_width),
            y: (world_pos.z * 10.0 + self.screen_height / 2.0).clamp(0.0, self.screen_height),
        })
    }

    pub fn set_screen_size(&mut self, width: f32, height: f32) {
        self.screen_width = width;
        self.screen_height = height;
    }
}

